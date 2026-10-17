"""One bounded, isolated export invocation; stdout contains fixed stage telemetry only."""
from __future__ import annotations
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import sys

from vrca_project_restore import restore, sha256, inventory

EXPORTER_SHA = {'win32': '58bb4c6a78507d77ea115db236ae7286b097979fba7f77aa247c16a471499fff',
                'linux': '21ce7e76ffc64b56bedc113fe12876c10fdfa6851872a33c70a2c659b33f25b0'}
STAGES = {'starting', 'loading', 'exporting', 'restoring', 'checking_references', 'packaging', 'ready'}


def emit(stage, detail=None):
    if stage not in STAGES: raise ValueError('project_stage_invalid')
    payload = {'stage': stage}
    for key, value in (detail or {}).items():
        if key in {'files', 'bytes'} and isinstance(value, int) and 0 <= value <= 16 * 1024**3:
            payload[key] = value
    print(json.dumps(payload), flush=True)


def full_export(executable, source, raw, timeout=540, notify=None):
    """HTTP completion plus stable output, never filesize-only success."""
    executable, source, raw = map(lambda p: Path(p).resolve(), (executable, source, raw))
    if raw.exists(): raise ValueError('project_raw_output_exists')
    if sha256(executable) != EXPORTER_SHA.get(sys.platform): raise ValueError('project_exporter_integrity')
    report = notify or emit
    raw.mkdir()
    # SDK/runtime assemblies are not loaded from the bundle into this Python process.
    process = subprocess.Popen([str(executable), '--headless', '--log-path', str(raw / 'exporter.log')],
        cwd=raw, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding='utf-8', errors='replace',
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    lines = queue.Queue(maxsize=128)
    stopped = threading.Event()
    def reader():
        try:
            for line in process.stdout:
                # Keep no untrusted object names, file paths or model values in product logs.
                match = re.search(r'listening on:\s*http://(?:127\.0\.0\.1|localhost):(\d+)', line, re.I)
                if match:
                    try: lines.put_nowait(int(match.group(1)))
                    except queue.Full: pass
        finally: stopped.set()
    threading.Thread(target=reader, daemon=True).start()
    try:
        began = time.monotonic()
        report('starting', {})
        port = None
        while time.monotonic() - began < 40:
            if stopped.is_set(): raise RuntimeError('project_exporter_start_failed')
            try: port = lines.get(timeout=1); break
            except queue.Empty: pass
        if not port: raise TimeoutError('project_exporter_start_timeout')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def post(route, form, limit):
            request = urllib.request.Request('http://127.0.0.1:%d%s' % (port, route),
                data=urllib.parse.urlencode(form).encode())
            with opener.open(request, timeout=limit) as response:
                # Export routes return bounded HTML, but no server HTML is stored or forwarded.
                if len(response.read(2 * 1024 * 1024 + 1)) > 2 * 1024 * 1024:
                    raise RuntimeError('project_exporter_response_limit')
        report('loading', {})
        post('/LoadFile', {'path': str(source)}, min(timeout, 240))
        destination = raw / 'data'; destination.mkdir()
        report('exporting', {})
        done = threading.Event(); errors = []
        def export():
            try: post('/Export/UnityProject', {'path': str(destination)}, timeout); done.set()
            except Exception: errors.append(True)
        threading.Thread(target=export, daemon=True).start()
        last = None; stable = 0
        while time.monotonic() - began < timeout:
            if process.poll() is not None: raise RuntimeError('project_exporter_exited')
            if errors: raise RuntimeError('project_exporter_request_failed')
            files = inventory(destination)
            stats = (len(files), sum(p.stat().st_size for p in files))
            stable = stable + 1 if stats == last else 0
            if stats != last: report('exporting', {'files': stats[0], 'bytes': stats[1]})
            last = stats
            if done.is_set() and stable >= 2:
                project = destination / 'ExportedProject'
                if not (project / 'Assets').is_dir(): raise RuntimeError('project_exporter_incomplete')
                return project
            time.sleep(1)
        raise TimeoutError('project_exporter_timeout')
    finally:
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)


def run(args):
    source = Path(args.source).resolve()
    if source.stat().st_size > 450 * 1024**2 or sha256(source) != args.source_sha:
        raise ValueError('project_source_integrity')
    work = Path(args.work).resolve()
    if work.exists(): raise ValueError('project_work_exists')
    work.mkdir(mode=0o700)
    raw = full_export(args.executable, source, work / 'raw')
    result = restore(raw, work / 'artifacts', source, args.sdk_root, emit)
    if result.get('sourceSha256') != args.source_sha: raise ValueError('project_source_integrity')
    emit('ready')
    return 0


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    for option in ('source', 'source-sha', 'work', 'sdk-root', 'executable'):
        p.add_argument('--' + option, required=True)
    args = p.parse_args()
    try: raise SystemExit(run(args))
    except Exception as error:
        # Only fixed error identifiers leave the worker. Native failures are handled by supervisor.
        code = str(error)
        if not re.fullmatch(r'project_[a-z_]+|sdk_[a-z_]+', code): code = 'project_export_failed'
        print(json.dumps({'error': code}), flush=True)
        raise SystemExit(1)

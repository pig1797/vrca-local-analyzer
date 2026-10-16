"""Loopback-only browser UI. No licence service, external assets or telemetry."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit
import webbrowser

# Windows embeddable Python intentionally omits the script directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import AnalysisError, ROOT, analyze, find_worker

MAX_UPLOAD = 450 * 1024 * 1024
MAX_RESULT = 24 * 1024 * 1024
TTL = 600
STAGES = {"hashing", "extracting", "analyzing", "deep_read", "deep_analyze", "verifying"}
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          **{"/" + name: (name, mime) for name, mime in [
              ("styles.css", "text/css"), ("analysis.css", "text/css"),
              ("wheel.css", "text/css"), ("local.css", "text/css"),
              ("wheel.js", "text/javascript"), ("local.js", "text/javascript")]}}


def menu_dto(path: Path, digest: str) -> dict:
    # Metadata only: no model pixels, asset extraction or arbitrary file URLs.
    if path.stat().st_size > 64 * 1024 * 1024:
        raise AnalysisError("结构图超过轮盘预览限制。")
    graph = json.loads(path.read_text(encoding="utf-8"))
    menus = graph.get("menus", [])
    if not isinstance(menus, list) or len(menus) > 4096:
        raise AnalysisError("轮盘数量超过预览限制。")
    kinds = {1: "Button", 2: "Toggle", 3: "SubMenu", 5: "TwoAxisPuppet",
             6: "FourAxisPuppet", 7: "RadialPuppet"}
    output, total = [], 0
    for menu in menus:
        controls = menu.get("controls", [])
        total += len(controls)
        if len(controls) > 128 or total > 32768:
            raise AnalysisError("轮盘控件超过预览限制。")
        rows = []
        for i, row in enumerate(controls):
            value = row.get("value", 0)
            rows.append(dict(id=f"{menu['id']}_{i}", name=str(row.get("name", ""))[:512],
                type=kinds.get(row.get("type"), "Unknown"), icon=None,
                iconState="not_requested", submenu=str(row.get("submenu", "")),
                parameter=str(row.get("parameter", ""))[:512],
                value=value if isinstance(value, (int, float)) and math.isfinite(value) else 0,
                subParameters=row.get("preview_sub_parameters", [])[:4]))
        output.append(dict(id=str(menu["id"]), name=str(menu.get("name", ""))[:512], controls=rows))
    ids = {m["id"] for m in output}
    roots = [str(r) for r in graph.get("active_root_menu_ids", []) if str(r) in ids]
    if not roots:
        children = {r["submenu"] for m in output for r in m["controls"]}
        roots = [m["id"] for m in output if m["id"] not in children]
    if not roots and output:
        roots = [output[0]["id"]]
    return dict(ok=True, schema=1, source_sha256=digest, menus=output,
                roots=[dict(id=r) for r in roots], root=roots[0] if roots else "")


def job_main(folder: Path, worker: Path, timeout: float) -> int:
    # This subprocess owns its extractor/worker children. Cancellation kills
    # only this process tree, never other tools or user processes.
    def progress(stage):
        temporary = folder / "progress.tmp"
        temporary.write_text(stage, encoding="ascii")
        temporary.replace(folder / "progress")

    menu = None
    def capture(path, digest):
        nonlocal menu
        try:
            menu = menu_dto(path, digest)
        except (AnalysisError, ValueError, TypeError, KeyError, OSError):
            menu = None  # Preview failure must not falsify the analysis result.
    try:
        report = analyze(folder / "input.vrca", worker, timeout,
                         progress=progress, menu_callback=capture, temp_parent=folder)
        payload = json.dumps(dict(report=report, menu=menu), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")
        if len(payload) > MAX_RESULT:
            raise AnalysisError("报告超过本地页面大小限制。")
        (folder / "result.json").write_bytes(payload)
        return 0
    except Exception as exc:
        # No exception paths/model names/third-party stderr in public logs.
        message = str(exc) if isinstance(exc, AnalysisError) else "本地解析失败；请检查文件和依赖，或更换模型重试。"
        (folder / "error.json").write_text(json.dumps(dict(error=message), ensure_ascii=False), encoding="utf-8")
        return 1


class LocalApp:
    def __init__(self, worker, timeout=180, runner=None):
        self.worker, self.timeout = worker, timeout
        self.root = Path(tempfile.mkdtemp(prefix="vrca-browser-"))
        self.lock = threading.RLock()
        self.job = None
        self.closed = False
        self.uploads = {}
        self.runner = runner or self.launch

    def launch(self, folder):
        options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
        else:
            options["start_new_session"] = True
        return subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
            "--job", str(folder), "--worker", str(self.worker), "--timeout", str(self.timeout)], **options)

    def reserve(self):
        with self.lock:
            if self.closed:
                raise AnalysisError("本地服务正在退出。")
            self.refresh()
            if self.job and self.job["state"] in ("uploading", "running"):
                raise AnalysisError("已有模型正在处理，请先取消或等待完成。")
            self.clear()
            import uuid
            identity = uuid.uuid4().hex
            folder = self.root / identity
            folder.mkdir()
            self.job = dict(id=identity, folder=folder, state="uploading", process=None,
                            created=time.monotonic(), finished=None, error=None)
            return self.job

    def begin(self, job):
        with self.lock:
            if self.closed or self.job is not job or job["state"] != "uploading":
                raise AnalysisError("上传已取消，请重新选择文件。")
            try:
                job["process"] = self.runner(job["folder"])
                job["state"] = "running"
            except OSError:
                self.fail(job, "无法启动本地分析组件，请检查运行环境。")

    def fail(self, job, error):
        with self.lock:
            if self.job is job and job["state"] == "uploading":
                job.update(state="failed", error=error, finished=time.monotonic())
                (job["folder"] / "input.vrca").unlink(missing_ok=True)

    def refresh(self):
        job = self.job
        if not job:
            return
        proc = job["process"]
        if job["state"] == "running" and proc.poll() is not None:
            ok = proc.returncode == 0 and (job["folder"] / "result.json").is_file()
            job.update(state="done" if ok else "failed", finished=time.monotonic())
            if not ok:
                try:
                    job["error"] = json.loads((job["folder"] / "error.json").read_text(encoding="utf-8"))["error"]
                except (OSError, ValueError, KeyError):
                    job["error"] = "本地组件退出，未生成有效结果；可更换文件重试。"
            (job["folder"] / "input.vrca").unlink(missing_ok=True)
        # Whole-job wall clock, not an endlessly renewed timeout.
        if job["state"] == "running" and time.monotonic() - job["created"] > self.timeout * 4 + 30:
            self.stop(job)
            job.update(state="failed", error="分析超过总时限；原模型未修改。", finished=time.monotonic())
        if job["finished"] is not None and time.monotonic() - job["finished"] > TTL:
            self.clear()

    def stop(self, job):
        proc = job.get("process")
        if proc and proc.poll() is None:
            if os.name == "nt":
                subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"),
                    "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait(timeout=15)

    def clear(self):
        if self.job:
            self.stop(self.job)
            shutil.rmtree(self.job["folder"])
            self.job = None

    def close(self):
        with self.lock:
            self.closed = True
            pending = list(self.uploads.items())
        for connection, finished in pending:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for connection, finished in pending:
            finished.wait(5)
        with self.lock:
            self.clear()
            shutil.rmtree(self.root)

    def status(self, identity):
        with self.lock:
            self.refresh()
            job = self.job
            if not job or job["id"] != identity:
                return None
            stage = ""
            try:
                stage = (job["folder"] / "progress").read_text(encoding="ascii")
            except OSError:
                pass
            return dict(id=identity, state=job["state"], stage=stage if stage in STAGES else "",
                        error=job["error"], expires_in=max(0, TTL - int(time.monotonic() - job["finished"]))
                        if job["finished"] else None)


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, app, port=0):
        self.app = app
        self.slots = threading.BoundedSemaphore(12)
        super().__init__(("127.0.0.1", port), Handler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = "http://" + self.authority

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "VRCA-Local"
    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(120)

    def reply(self, status, payload, mime="application/json; charset=utf-8"):
        if not isinstance(payload, bytes):
            payload = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(payload)

    def allowed(self, api=False):
        # Reject DNS rebinding and browser cross-origin requests. Local apps
        # running as the same OS user are not a separate security boundary.
        ok = (self.headers.get_all("Host") == [self.server.authority]
              and self.headers.get("Origin", self.server.origin) == self.server.origin
              and self.headers.get("Sec-Fetch-Site", "none") in ("same-origin", "none")
              and (not api or self.headers.get("X-VRCA-Local") == "1"))
        if not ok:
            self.reply(403, dict(error="仅允许本机页面同源访问。"))
        return ok

    def do_GET(self):
        route = urlsplit(self.path).path
        if not self.allowed(api=route.startswith("/api/")):
            return
        if route in ASSETS:
            name, mime = ASSETS[route]
            self.reply(200, (ROOT / "web" / name).read_bytes(), mime)
        elif route == "/api/health":
            self.reply(200, dict(ok=True, local=True, max_upload=MAX_UPLOAD, writeback=False, export=False))
        else:
            match = re.fullmatch(r"/api/analyses/([a-f0-9]{32})(/result)?", route)
            if not match:
                self.reply(404, dict(error="不存在的入口。"))
                return
            with self.server.app.lock:
                status = self.server.app.status(match[1])
                if status is None:
                    self.reply(404, dict(error="任务已清理，请重新选择模型。"))
                elif match[2]:
                    if status["state"] != "done":
                        self.reply(409, dict(error="分析尚未完成。"))
                    else:
                        path = self.server.app.job["folder"] / "result.json"
                        if path.stat().st_size > MAX_RESULT:
                            self.reply(500, dict(error="报告超出大小限制。"))
                        else:
                            self.reply(200, path.read_bytes())
                else:
                    self.reply(200, status)

    def do_POST(self):
        if not self.allowed(api=True):
            return
        if self.path == "/api/shutdown":
            self.reply(200, dict(ok=True))
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if self.path != "/api/analyses":
            self.reply(404, dict(error="不存在的入口。"))
            return
        size = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or len(size) != 1 or len(size[0]) > 12 or not size[0].isascii() or not size[0].isdigit():
            self.reply(411, dict(error="上传需要明确的文件大小。"))
            return
        length = int(size[0])
        if length < 8 or length > MAX_UPLOAD:
            self.reply(413, dict(error="请选择 450 MiB 以内的非空 VRCA 文件。"))
            return
        name = unquote(self.headers.get("X-File-Name", ""))
        if not name.lower().endswith(".vrca"):
            self.reply(400, dict(error="只接受 .vrca 文件。"))
            return
        app, job = self.server.app, None
        finished = threading.Event()
        with app.lock:
            if app.closed:
                self.reply(503, dict(error="本地服务正在退出。"))
                return
            app.uploads[self.connection] = finished
        try:
            job = app.reserve()
            with (job["folder"] / "input.vrca").open("xb") as stream:
                remaining = length
                signature = self.rfile.read(min(8, remaining))
                if signature != b"UnityFS\x00":
                    raise AnalysisError("文件不是受支持的 UnityFS VRCA 包，请重新选择。")
                stream.write(signature)
                remaining -= len(signature)
                while remaining:
                    if app.closed or time.monotonic() - job["created"] > 120:
                        raise AnalysisError("本机接收已停止或超时，请重新启动后重试。")
                    data = self.rfile.read(min(1024 * 1024, remaining))
                    if not data:
                        raise AnalysisError("上传中断，请重新选择文件。")
                    stream.write(data)
                    remaining -= len(data)
            app.begin(job)
            self.reply(202, dict(id=job["id"]))
        except AnalysisError as exc:
            if job:
                app.fail(job, str(exc))
            self.reply(409 if job is None else 400, dict(error=str(exc)))
        except (OSError, TimeoutError):
            if job:
                app.fail(job, "本机接收文件失败，请重试或检查临时磁盘空间。")
            self.reply(400, dict(error="本机接收文件失败，请重试或检查临时磁盘空间。"))
        finally:
            with app.lock:
                app.uploads.pop(self.connection, None)
            finished.set()

    def do_DELETE(self):
        if not self.allowed(api=True):
            return
        match = re.fullmatch(r"/api/analyses/([a-f0-9]{32})", self.path)
        app = self.server.app
        with app.lock:
            if not match or not app.job or app.job["id"] != match[1]:
                self.reply(404, dict(error="任务已清理。"))
                return
            app.clear()
            self.reply(200, dict(ok=True))


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="启动 VRCA 本地网页，所有分析只在本机执行。")
    parser.add_argument("--worker")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--job", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 600 or not 0 <= args.port <= 65535:
        parser.error("超时须为 1–600 秒，端口须为 0–65535。")
    try:
        worker = find_worker(args.worker)
        if args.job:
            return job_main(args.job, worker, args.timeout)
        import importlib.util
        if importlib.util.find_spec("UnityPy") is None:
            raise AnalysisError("缺少 UnityPy，请按 README 安装依赖或使用完整便携包。")
        app = LocalApp(worker, args.timeout)
        server = None
        done = threading.Event()
        try:
            server = LocalServer(app, args.port)
            def maintain():
                while not done.wait(1):
                    with app.lock:
                        app.refresh()
            threading.Thread(target=maintain, daemon=True).start()
            print(f"VRCA 本地网页：{server.origin}/", flush=True)
            print("模型仅在本机处理。关闭本窗口或点击网页“退出本地服务”即可退出。", flush=True)
            if not args.no_browser:
                if not webbrowser.open(server.origin + "/"):
                    print("浏览器未自动打开，请手动打开上面的本机地址。", flush=True)
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            done.set()
            if server:
                server.server_close()
            app.close()
        return 0
    except (AnalysisError, OSError) as exc:
        print(f"启动失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

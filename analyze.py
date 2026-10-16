"""Local, read-only VRCA analysis. No licence server or upload is used."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
MAX_REPORT_BYTES = 16 * 1024 * 1024


class AnalysisError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_stage(command: list[str], timeout: float) -> bytes:
    # The extractor's progress and exception text may contain private names.
    # Capture it, but do not include it in public console diagnostics.
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as exc:
        raise AnalysisError("本地分析超时；原模型未修改。") from exc
    except OSError as exc:
        raise AnalysisError("无法启动本地组件，请检查 Python、依赖和 worker 路径。") from exc
    if proc.returncode != 0:
        raise AnalysisError(f"本地组件失败（退出码 {proc.returncode}）；没有生成有效结果。")
    return proc.stdout


def analyze_graph(worker: Path, graph: Path, digest: str, timeout: float) -> dict:
    data = run_stage([str(worker), "analyze-graph", str(graph), "--json"], timeout)
    if len(data) > MAX_REPORT_BYTES:
        raise AnalysisError("分析报告超出大小限制。")
    try:
        report = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise AnalysisError("分析组件未返回有效 JSON。") from exc
    if not isinstance(report, dict) or str(report.get("source_sha256", "")).lower() != digest:
        raise AnalysisError("分析报告与当前输入不匹配，已拒绝输出。")
    if report.get("graph_sha256") != sha256(graph):
        raise AnalysisError("图谱摘要不匹配，已拒绝输出。")
    return report


def analyze(source: Path, worker: Path, timeout: float = 180, *, progress=None,
            menu_callback=None, temp_parent=None) -> dict:
    notify = progress or (lambda stage: None)
    notify("hashing")
    digest = sha256(source)
    adapter = ROOT / "python" / "vrca_extract_graph.py"
    with tempfile.TemporaryDirectory(prefix="vrca-local-", dir=temp_parent) as folder:
        directory = Path(folder)
        graph = directory / "fast.graph.json"
        notify("extracting")
        run_stage([sys.executable, str(adapter), "--remote-graph",
                   str(source), str(graph)], timeout)
        if menu_callback:
            menu_callback(graph, digest)
        notify("analyzing")
        report = analyze_graph(worker, graph, digest, timeout)
        deep_passes = 0
        request = report.get("deep_scan_request")
        if isinstance(request, dict) and request.get("controllers"):
            # Exactly one targeted deep pass; never repeat indefinitely or
            # reinterpret missing evidence as a verified password.
            request_path = directory / "deep.request.json"
            request_path.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
            deep_graph = directory / "deep.graph.json"
            notify("deep_read")
            run_stage([sys.executable, str(adapter), "--remote-deep-from-fast",
                       str(graph), str(request_path), str(source), str(deep_graph)], timeout)
            notify("deep_analyze")
            report = analyze_graph(worker, deep_graph, digest, timeout)
            deep_passes = 1
        notify("verifying")
        if sha256(source) != digest:
            raise AnalysisError("输入文件在分析期间发生变化，已拒绝输出。")
        report["local_execution"] = {
            "network_used": False,
            "input_modified": False,
            "targeted_deep_passes": deep_passes,
            "runtime_tested": False,
            "model_writeback_supported": False,
        }
        return report


def find_worker(explicit: str | None) -> Path:
    if explicit:
        candidates = [Path(explicit).expanduser()]
    else:
        suffix = ".exe" if os.name == "nt" else ""
        candidates = [ROOT / "bin" / ("VrcAnalysisWorker" + suffix),
                      ROOT / "build" / ("VrcAnalysisWorker" + suffix),
                      ROOT / "build" / "Release" / ("VrcAnalysisWorker" + suffix)]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise AnalysisError("未找到 VrcAnalysisWorker，请先按 README 编译，或传入 --worker。")


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="在本机只读分析 VRCA，无需卡密或服务器。")
    parser.add_argument("model", type=Path)
    parser.add_argument("--worker", help="本地编译的 VrcAnalysisWorker 路径")
    parser.add_argument("--output", type=Path, help="另存 JSON；已有文件不会覆盖")
    parser.add_argument("--timeout", type=float, default=180,
                        help="每个子进程的超时秒数，范围 1–600，默认 180")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.timeout <= 600:
            raise AnalysisError("--timeout 必须介于 1 和 600 秒。")
        if args.model.is_symlink() or not args.model.is_file():
            raise AnalysisError("输入必须是普通文件，不能是符号链接。")
        source = args.model.resolve()
        if args.output and args.output.exists():
            raise AnalysisError("输出文件已存在；请指定新文件名。")
        report = analyze(source, find_worker(args.worker), args.timeout)
        payload = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
            print("分析完成，JSON 已保存。原模型未修改。", file=sys.stderr)
        else:
            # Python defaults to the Windows console codepage when redirected.
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            sys.stdout.write(payload)
        return 0
    except (AnalysisError, OSError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

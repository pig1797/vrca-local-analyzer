"""Native CLI integration: synthetic graph, Unicode paths and bad inputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_contact_guard_password_confidence import fixture


def main():
    worker = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="vrca-interface-") as folder:
        directory = Path(folder) / "中文目录_Unicode"
        directory.mkdir()
        graph, expected = fixture(109, "targeted_deep", with_contact=False)
        path = directory / "合成图谱.json"
        path.write_text(json.dumps(graph), encoding="utf-8")
        proc = subprocess.run([worker, "analyze-graph", str(path), "--json"],
                              capture_output=True, timeout=20)
        assert proc.returncode == 0, (f"Unicode-path analysis failed: "
            f"exit={proc.returncode}, hex=0x{proc.returncode & 0xffffffff:08x}, "
            f"stderr={proc.stderr[:200]!r}")
        report = json.loads(proc.stdout)
        assert report["graph_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert report["source_sha256"] == graph["source_sha256"]
        assert any(row["password"] == expected for row in report["results"])
        original = path.read_bytes()
        for args, code in [([], 64), (["analyze-graph", "relative.json", "--json"], 65),
                           (["analyze-graph", str(directory / "missing.json"), "--json"], 65)]:
            failure = subprocess.run([worker, *args], capture_output=True, timeout=10)
            assert failure.returncode == code, "CLI rejection changed"
            assert not failure.stdout, "Failure returned a success report"
        path.write_bytes(b"not-json")
        failure = subprocess.run([worker, "analyze-graph", str(path), "--json"],
                                 capture_output=True, timeout=10)
        assert failure.returncode == 65 and not failure.stdout
        path.write_bytes(original)
        assert path.read_bytes() == original
    print("WORKER_INTERFACE_OK|checks=9|synthetic_only=true")


if __name__ == "__main__":
    main()

"""Local orchestration tests using synthetic bytes and mocked subprocesses."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("local_analysis", Path(__file__).resolve().parents[1] / "analyze.py")
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="local-launcher-test-")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "synthetic.vrca"
        self.source.write_bytes(b"SYNTHETIC-NOT-A-REAL-MODEL")
        self.worker = Path(self.temp.name) / "worker"
        self.worker.write_bytes(b"not-executed")

    def pipeline(self, deep=False, mutate=False, keep_request=False):
        calls = []
        digest = local.sha256(self.source)
        request = dict(schema=1, source_sha256=digest,
                       controllers=[dict(path_id="1", machine_indices=[0])])

        def run(command, timeout):
            calls.append(command)
            if "analyze-graph" not in command:
                Path(command[-1]).write_text("{}", encoding="utf-8")
                return b"STAGE|synthetic"
            report = dict(source_sha256=digest, graph_sha256=local.sha256(Path(command[2])),
                          results=[], password_candidates=[])
            if deep and (len(calls) < 4 or keep_request):
                report.update(deep_scan_request=request, analysis_incomplete=True)
            if mutate:
                self.source.write_bytes(b"changed-synthetic-input")
            return json.dumps(report).encode()

        return calls, run

    def test_fast_only_and_cleanup(self):
        calls, run = self.pipeline()
        original = self.source.read_bytes()
        with patch.object(local, "run_stage", side_effect=run):
            report = local.analyze(self.source, self.worker)
        self.assertEqual(len(calls), 2)
        self.assertFalse(Path(calls[0][-1]).exists())
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(report["local_execution"]["targeted_deep_passes"], 0)

    def test_targeted_deep_exactly_once(self):
        calls, run = self.pipeline(deep=True)
        with patch.object(local, "run_stage", side_effect=run):
            report = local.analyze(self.source, self.worker)
        self.assertEqual(len(calls), 4)
        self.assertIn("--remote-deep-from-fast", calls[2])
        self.assertEqual(report["local_execution"]["targeted_deep_passes"], 1)

    def test_unresolved_evidence_is_not_promoted(self):
        calls, run = self.pipeline(deep=True, keep_request=True)
        with patch.object(local, "run_stage", side_effect=run):
            report = local.analyze(self.source, self.worker)
        self.assertEqual(len(calls), 4)
        self.assertTrue(report["analysis_incomplete"])
        self.assertEqual(report["results"], [])

    def test_changed_input_is_rejected(self):
        _, run = self.pipeline(mutate=True)
        with patch.object(local, "run_stage", side_effect=run):
            with self.assertRaises(local.AnalysisError):
                local.analyze(self.source, self.worker)

    def test_wrong_report_source_is_rejected(self):
        with patch.object(local, "run_stage", return_value=b'{"source_sha256":"wrong"}'):
            with self.assertRaises(local.AnalysisError):
                local.analyze_graph(self.worker, self.source, local.sha256(self.source), 1)

    def test_wrong_graph_hash_is_rejected(self):
        report = dict(source_sha256=local.sha256(self.source), graph_sha256="wrong")
        with patch.object(local, "run_stage", return_value=json.dumps(report).encode()):
            with self.assertRaises(local.AnalysisError):
                local.analyze_graph(self.worker, self.source, report["source_sha256"], 1)

    def test_non_json_report_is_rejected(self):
        with patch.object(local, "run_stage", return_value=b"not-json"):
            with self.assertRaises(local.AnalysisError):
                local.analyze_graph(self.worker, self.source, "0" * 64, 1)

    def test_timeout_is_bounded(self):
        with patch.object(local.subprocess, "run", side_effect=subprocess.TimeoutExpired(["synthetic"], 1)):
            with self.assertRaises(local.AnalysisError):
                local.run_stage(["synthetic"], 1)

    def test_failed_component_does_not_leak_stderr(self):
        result = subprocess.CompletedProcess(["synthetic"], 2, b"", b"PRIVATE-SYNTHETIC-MARKER")
        with patch.object(local.subprocess, "run", return_value=result):
            with self.assertRaises(local.AnalysisError) as failure:
                local.run_stage(["synthetic"], 1)
        self.assertNotIn("PRIVATE-SYNTHETIC-MARKER", str(failure.exception))

    def test_existing_output_is_preserved(self):
        output = Path(self.temp.name) / "existing.json"
        output.write_bytes(b"keep-this")
        with patch.object(local, "analyze") as analyze:
            with patch("sys.stderr"):
                code = local.main([str(self.source), "--output", str(output)])
        self.assertEqual(code, 1)
        self.assertEqual(output.read_bytes(), b"keep-this")
        analyze.assert_not_called()

    def test_output_json_and_source_unchanged(self):
        output = Path(self.temp.name) / "new.report.json"
        with patch.object(local, "analyze", return_value={"results": []}):
            with patch("sys.stderr"):
                code = local.main([str(self.source), "--worker", str(self.worker), "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"results": []})

    def test_invalid_timeout_and_missing_worker(self):
        with patch("sys.stderr"):
            self.assertEqual(local.main([str(self.source), "--timeout", "nan"]), 1)
        with self.assertRaises(local.AnalysisError):
            local.find_worker(str(Path(self.temp.name) / "missing"))

    def test_oversized_report_is_rejected(self):
        with patch.object(local, "MAX_REPORT_BYTES", 4):
            with patch.object(local, "run_stage", return_value=b"long-report"):
                with self.assertRaises(local.AnalysisError):
                    local.analyze_graph(self.worker, self.source, "0" * 64, 1)


if __name__ == "__main__":
    unittest.main()

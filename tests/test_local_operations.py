"""Selection boundary tests, synthetic reports only; never bypass the core."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import local_operations as ops
from analyze import AnalysisError


class OperationContracts(unittest.TestCase):
    def report(self):
        return dict(engine="VrcNativeCore/cpp", source_sha256="a" * 64,
                    state_bypasses=[dict(path_id="123", machine_index=0, before=0,
                        unlock_state=1, unlock_state_name="terminal", method="native_named_unlock_semantic_terminal")],
                    plan_options=[dict(option_id="b" * 64)])

    def test_no_plan_and_mixed_plan_fail_closed(self):
        self.assertIsNotNone(ops.capability({}))
        report = self.report()
        self.assertIsNone(ops.capability(report))
        for key, value in [("menu_bypasses", [{}]), ("object_removals", [{}]),
                           ("external_input_lock", True), ("manual_unlock_candidates", [{}]),
                           ("deep_analysis_request", {}), ("plan_options", [])]:
            changed = copy.deepcopy(report); changed[key] = value or ([{}] if key.endswith("request") else value)
            self.assertIsNotNone(ops.capability(changed), key)
        changed = copy.deepcopy(report); changed["state_bypasses"][0]["unknown_edit"] = True
        self.assertIsNotNone(ops.capability(changed))

    def test_scope_must_cover_exact_report(self):
        report = self.report()
        scoped = dict(status="ready", state_bypasses=[])
        with self.assertRaises(AnalysisError): ops.make_plan(report, scoped, {})
        scoped["state_bypasses"] = copy.deepcopy(report["state_bypasses"])
        with self.assertRaises(AnalysisError): ops.make_plan(report, scoped, {"source_sha256": "c" * 64})
        with self.assertRaises(AnalysisError): ops.make_plan(report, scoped, {"source_sha256": "a" * 64, "controllers": []})

    def test_equivalent_proof_cannot_add_another_target(self):
        report = self.report()
        row = report["state_bypasses"][0]
        primary = dict(row)
        other = dict(row, unlock_state=2)
        row["equivalent_proofs"] = [primary, other]
        with self.assertRaises(AnalysisError):
            ops.make_plan(report, dict(status="ready", state_bypasses=report["state_bypasses"]), {"source_sha256": "a" * 64})

    def test_export_missing_dependencies_never_returns_artifact(self):
        import tempfile
        with tempfile.TemporaryDirectory() as name:
            with patch.object(ops, "ROOT", Path(name)):
                with self.assertRaises(AnalysisError): ops.export(Path(name), lambda _: None)


if __name__ == "__main__": unittest.main()

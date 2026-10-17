"""Owned local write/export orchestration. No client-supplied plans or paths."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import sys

from analyze import ROOT, AnalysisError, run_stage, sha256

PY = ROOT / "python"
OTHER = ("menu_bypasses", "condition_rewrites", "object_edits", "object_removals")
FIELDS = ("path_id", "machine_index", "before", "unlock_state", "unlock_state_name", "method")
META = set(FIELDS) | {"field", "proof_family", "depends_on", "dependencies", "equivalent_proofs"}


def capability(report):
    if report.get("engine") != "VrcNativeCore/cpp" or not report.get("state_bypasses"):
        return "未得到可安全执行的永久移除计划。"
    if (any(report.get(k) for k in OTHER) or report.get("external_input_lock")
            or report.get("avacrypt_v1_mesh_solution") or report.get("menu_recovery_needed")
            or report.get("record_keypad") or report.get("manual_unlock_candidates")):
        return "该模型包含当前本地写回器不支持的混合操作。"
    if report.get("deep_analysis_request") or report.get("confirmation_deep_scan_request"):
        return "永久移除仍缺少必要证据。"
    records, options = report["state_bypasses"], report.get("plan_options", [])
    if len(records) not in (1, 2) or not options or len(options) > 64:
        return "计划数量或依赖关系不满足写回条件。"
    if any(not isinstance(r, dict) or set(r) - META for r in records):
        return "计划包含未知字段，已停止写回。"
    return None


def make_plan(report, scoped, graph):
    reason = capability(report)
    if reason:
        raise AnalysisError(reason)
    if (scoped.get("status") != "ready" or scoped.get("state_bypasses") != report["state_bypasses"]
            or any(scoped.get(k) for k in OTHER)):
        raise AnalysisError("核心未确认完整计划范围，已停止写回。")
    if graph.get("source_sha256", "").lower() != report["source_sha256"].lower():
        raise AnalysisError("图谱与原文件不匹配。")
    records = []
    for row in scoped["state_bypasses"]:
        proofs = row.get("equivalent_proofs")
        if proofs is not None:
            primary = {k: v for k, v in row.items() if k != "equivalent_proofs"}
            if not isinstance(proofs, list) or not 2 <= len(proofs) <= 64 or proofs[0] != primary:
                raise AnalysisError("等价证明不完整。")
            for proof in proofs:
                if (set(proof) - (META - {"equivalent_proofs"}) or proof.get("depends_on")
                        or proof.get("dependencies") or any(proof.get(k) != row.get(k) for k in FIELDS[:-1])):
                    raise AnalysisError("等价证明的目标不一致。")
        if row.get("dependencies") or row.get("field", "m_DefaultState") != "m_DefaultState":
            raise AnalysisError("不支持该字段或未闭合依赖。")
        controllers = [c for c in graph.get("controllers", []) if c.get("path_id") == row["path_id"]]
        if len(controllers) != 1:
            raise AnalysisError("目标控制器不唯一。")
        machine = controllers[0]["machines"][row["machine_index"]]
        if (machine["default_state"] != row["before"]
                or machine["states"][row["unlock_state"]]["name"] != row["unlock_state_name"]):
            raise AnalysisError("目标状态与图谱不一致。")
        record = {k: row[k] for k in FIELDS}
        record["field"] = "m_DefaultState"
        if len(scoped["state_bypasses"]) == 2:
            record["proof_family"] = row["proof_family"]
            if "depends_on" in row:
                record["depends_on"] = row["depends_on"]
        elif row.get("depends_on"):
            raise AnalysisError("依赖计划不完整。")
        records.append(record)
    plan = dict(engine="VrcNativeCore/cpp", source_sha256=report["source_sha256"], state_bypasses=records,
                **{k: [] for k in OTHER})
    # Independent narrow schema validation, including allowed methods and pair.
    sys.path.insert(0, str(PY))
    from state_writer import validate_plan, SAFE_STATE_METHODS
    validate_plan(plan, report["source_sha256"])
    if any(p["method"] not in SAFE_STATE_METHODS for r in scoped["state_bypasses"] for p in r.get("equivalent_proofs", [])):
        raise AnalysisError("等价证明方法不受支持。")
    return plan


def remove(folder, worker, progress):
    evidence = folder / "evidence"
    report_path, graph_path = evidence / "report.json", evidence / "graph.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    source = folder / "input.vrca"
    digest = sha256(source)
    if digest != report["source_sha256"].lower() or sha256(graph_path) != report["graph_sha256"]:
        raise AnalysisError("原文件或分析图谱发生变化，已拒绝写回。")
    reason = capability(report)
    if reason:
        raise AnalysisError(reason)
    out = folder / "remove"
    out.mkdir()
    selection = sorted(o["option_id"] for o in report["plan_options"])
    selection_path = out / "selection.json"
    selection_path.write_text(json.dumps(dict(selected_option_ids=selection)), encoding="utf-8")
    progress("planning")
    scoped = json.loads(run_stage([str(worker), "scope-plan", str(report_path), str(selection_path), "--json"], 60))
    for key, expected in (("source_sha256", digest), ("report_sha256", sha256(report_path)),
                          ("selection_sha256", sha256(selection_path)), ("policy_hash", report["policy_hash"])):
        if scoped.get(key, "").lower() != expected.lower():
            raise AnalysisError("核心计划摘要不匹配。")
    if (scoped.get("policy_version") != report["policy_version"]
            or sorted(scoped.get("selected_option_ids", [])) != selection
            or sorted(scoped.get("resolved_option_ids", [])) != selection):
        raise AnalysisError("核心计划依赖未完整解析。")
    plan = make_plan(report, scoped, json.loads(graph_path.read_text(encoding="utf-8")))
    plan_path = out / "plan.json"
    plan_path.write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
    output = out / "unlocked.vrca"
    progress("writing")
    run_stage([sys.executable, str(PY / "state_writer.py"), str(source), str(plan_path), str(output)], 540)
    progress("reparsing")
    proof = json.loads(run_stage([sys.executable, str(PY / "verify_writeback.py"), str(source), str(output),
                                 str(output.with_suffix(".vrca.writer.json"))], 540))
    if (proof.get("status") != "passed" or proof.get("source_sha256", "").lower() != digest
            or proof.get("output_sha256", "").lower() != sha256(output) or sha256(source) != digest
            or proof.get("resource_and_non_target_bytes_preserved") is not True):
        raise AnalysisError("独立复验未通过，不提供下载。")
    return dict(ok=True, kind="remove", source_sha256=digest, runtime_verified=False,
                verification=proof, artifacts=[dict(key="model", name="unlocked.vrca", bytes=output.stat().st_size, sha256=sha256(output))])


def export(folder, progress, source_kind="original"):
    sys.path.insert(0, str(PY))
    from vrca_project_export import full_export
    from vrca_project_restore import restore
    suffix = ".exe" if os.name == "nt" else ""
    executable = ROOT / "tools" / "AssetRipper" / ("AssetRipper.GUI.Free" + suffix)
    sdk = ROOT / "tools" / "sdk"
    if not executable.is_file() or not (sdk / "com.vrchat.avatars/package.json").is_file():
        raise AnalysisError("缺少工程导出组件。请安装 README 指定的 AssetRipper 2.0.0 与 SDK 3.10.4。")
    source = folder / "input.vrca"
    if source_kind == "unlocked":
        receipt = json.loads((folder / "remove.result.json").read_text(encoding="utf-8"))
        source = folder / "remove/unlocked.vrca"
        if receipt.get("ok") is not True or sha256(source) != receipt["artifacts"][0]["sha256"]:
            raise AnalysisError("移除副本未通过验证。")
    digest = sha256(source)
    out = folder / "export"
    out.mkdir()
    raw = full_export(executable, source, out / "raw", notify=lambda stage, _: progress(stage))
    receipt = restore(raw, out / "artifacts", source, sdk, lambda stage, _: progress(stage))
    if receipt.get("sourceSha256") != digest or sha256(source) != digest or receipt.get("ok") is not True:
        raise AnalysisError("工程导出校验未通过。")
    return dict(ok=True, kind="export", source=source_kind, status=receipt["status"], counts=receipt["counts"],
                unity_import_verified=False, artifacts=[dict(a, key=a["kind"]) for a in receipt["artifacts"]])


def run(folder, worker, kind, source="original"):
    def progress(stage):
        tmp = folder / "operation.progress.tmp"
        tmp.write_text(stage, encoding="ascii")
        tmp.replace(folder / "operation.progress")
    try:
        result = remove(folder, worker, progress) if kind == "remove" else export(folder, progress, source)
        (folder / (kind + ".result.json")).write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        return 0
    except Exception as exc:
        message = str(exc) if isinstance(exc, AnalysisError) else "本地处理失败；未产生已验证下载，请检查组件、磁盘空间或更换模型。"
        (folder / (kind + ".error.json")).write_text(json.dumps(dict(error=message), ensure_ascii=False), encoding="utf-8")
        return 1

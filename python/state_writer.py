#!/usr/bin/env python3
"""Local state-only byte writer, called only after core scope/graph checks.

One m_DefaultState or an explicitly proved dependency pair only. Output must
pass the separate verify_writeback process before it is offered for download.
No licence/JTI/server credentials are needed for the local application.
"""
from __future__ import annotations

import argparse
import copy
import gc
import hashlib
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strict_lzma1ext import decompress_bytes, iter_decode
from unityfs_size_aware import install_bundle_reader, install_unitypy

try:
    import UnityPy
except ImportError as exc:  # pragma: no cover - exercised by deployment probe
    raise SystemExit("writer_requires_unitypy") from exc

import stream_serialized_assets as bundle


# This is a test-only ceiling.  The production extractor's 128 MiB probe
# guard is not changed by this module.  The server's worker process still has
# a separate hard memory/job limit before this code could be considered.
MAX_BLOCK_BYTES = 768 * 1024 * 1024
bundle.MAX_BLOCK_BYTES = MAX_BLOCK_BYTES
install_bundle_reader(bundle)
install_unitypy()
MAX_SOURCE_BYTES = 450 * 1024 * 1024
MAX_EXPANDED_BYTES = 768 * 1024 * 1024
MAX_TARGETS = 2  # A second target is legal only in the explicit dependency pair.
PAIR_METHOD = "native_guarded_numeric_dependency_terminal"
PRODUCER_FAMILY = "guarded_numeric_gate_producer_v1"
EFFECT_FAMILY = "guarded_numeric_effect_terminal_v1"

SAFE_STATE_METHODS = {
    "native_named_unlock",
    "native_named_unlock_semantic_terminal",
    "native_press_release_terminal",
    "native_press_release_semantic_terminal",
    "native_no_reset_sync_latch_terminal",
    "native_fail_stop_dual_saved_latch_terminal",
    "native_split_button_sentinel_buffer_terminal",
    "native_radial_window_terminal",
    "native_parallel_dial_terminal",
    "native_reset_guarded_terminal",
    "native_contact_guarded_semantic_terminal",
    "native_button_pulse_dispatch_terminal",
    "native_semantic_ir_terminal",
    "native_guarded_numeric_dependency_terminal",
    "native_random_boolean_restore_terminal",
    "native_compound_restriction_terminal",
    "native_float_range_gate_terminal",
    "native_osc_shift_restore_terminal",
    "native_boolean_toggle_and_terminal",
}

PLAN_KEYS = {
    "engine", "source_sha256", "state_bypasses", "menu_bypasses",
    "condition_rewrites", "object_edits", "object_removals",
}
STATE_KEYS = {
    "path_id", "machine_index", "before", "unlock_state",
    "unlock_state_name", "method", "field",
}
HEX64 = set("0123456789abcdefABCDEF")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def unwrap(value):
    while isinstance(value, dict) and set(value) == {"data"}:
        value = value["data"]
    return value


def exact_keys(value, expected, error):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(error)


def canonical_int64(value):
    if not isinstance(value, str) or not value or value == "-0":
        raise ValueError("plan_state_path_invalid")
    if value[0] == "-":
        digits = value[1:]
    else:
        digits = value
    if not digits.isdigit() or (len(digits) > 1 and digits[0] == "0"):
        raise ValueError("plan_state_path_invalid")
    parsed = int(value)
    if parsed == 0 or parsed < -(1 << 63) or parsed > (1 << 63) - 1:
        raise ValueError("plan_state_path_invalid")
    return parsed


def validate_plan(plan, source_sha256: str):
    """Validate the plan shape expected after Node signature verification."""
    exact_keys(plan, PLAN_KEYS, "plan_schema_invalid")
    if plan.get("engine") != "VrcNativeCore/cpp":
        raise ValueError("plan_identity_invalid")
    supplied = str(plan.get("source_sha256", ""))
    if len(supplied) != 64 or any(c not in HEX64 for c in supplied):
        raise ValueError("plan_identity_invalid")
    if supplied.upper() != source_sha256.upper():
        raise ValueError("plan_source_mismatch")
    for key in ("menu_bypasses", "condition_rewrites", "object_edits", "object_removals"):
        if not isinstance(plan.get(key), list) or plan[key]:
            raise ValueError("plan_not_state_only")
    records = plan.get("state_bypasses")
    if not isinstance(records, list) or len(records) not in (1, 2):
        raise ValueError("writer_requires_single_or_dependency_pair")
    for record in records:
        keys = set(STATE_KEYS)
        if len(records) == 2:
            keys.add("proof_family")
            if isinstance(record, dict) and record.get("proof_family") == EFFECT_FAMILY:
                keys.add("depends_on")
        exact_keys(record, keys, "plan_state_schema_invalid")
        canonical_int64(record.get("path_id"))
        for key in ("machine_index", "before", "unlock_state"):
            value = record.get(key)
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("plan_state_scope_invalid")
        if record["before"] == record["unlock_state"]:
            raise ValueError("plan_state_scope_invalid")
        if record.get("field") != "m_DefaultState":
            raise ValueError("writer_field_not_supported")
        if not isinstance(record.get("unlock_state_name"), str) or not record["unlock_state_name"]:
            raise ValueError("plan_state_scope_invalid")
        if record.get("method") not in SAFE_STATE_METHODS:
            raise ValueError("plan_state_method_not_allowed")
    if len(records) == 1:
        if records[0]["method"] == PAIR_METHOD:
            raise ValueError("plan_dependency_pair_incomplete")
        return records[0]
    producers = [r for r in records if r["proof_family"] == PRODUCER_FAMILY]
    effects = [r for r in records if r["proof_family"] == EFFECT_FAMILY]
    if len(producers) != 1 or len(effects) != 1 or any(r["method"] != PAIR_METHOD for r in records):
        raise ValueError("plan_dependency_pair_invalid")
    producer, effect = producers[0], effects[0]
    exact_keys(effect["depends_on"], {"path_id", "machine_index", "unlock_state"}, "plan_dependency_pair_invalid")
    if (producer["path_id"], producer["machine_index"]) == (effect["path_id"], effect["machine_index"]):
        raise ValueError("plan_dependency_pair_invalid")
    if effect["depends_on"] != {k: producer[k] for k in ("path_id", "machine_index", "unlock_state")}:
        raise ValueError("plan_dependency_pair_invalid")
    # bools compare equal to ints in Python: reject them in dependency fields.
    if type(effect["depends_on"]["machine_index"]) is not int or type(effect["depends_on"]["unlock_state"]) is not int:
        raise ValueError("plan_dependency_pair_invalid")
    return records


def preflight_bundle(source: Path):
    """Inspect bundle layout before UnityPy can expand any payload."""
    info = bundle.inspect(source)
    if info["expanded_size"] > MAX_EXPANDED_BYTES:
        raise ValueError("expanded_bundle_too_large")
    if not info["blocks"] or any(size <= 0 for size, _, _ in info["blocks"]):
        raise ValueError("bundle_blocks_invalid")
    if info["data_start"] + sum(compressed for _, compressed, _ in info["blocks"]) > info["size"]:
        raise ValueError("bundle_data_bounds_invalid")
    # The proof fixture has one first serialized node and resource nodes.
    # Do not generalise the local ObjectReader offsets to unproved multi-node
    # ownership/layouts merely because a controller PathID happens to match.
    serialized_nodes = [node for node in info["nodes"] if node["flags"] == 4]
    if (len(serialized_nodes) != 1 or serialized_nodes[0]["offset"] != 0 or
            any(node["flags"] not in (0, 4) for node in info["nodes"]) or
            len({node["name"] for node in info["nodes"]}) != len(info["nodes"])):
        raise ValueError("writer_serialized_layout_unsupported")
    if info["flags"] & ~0x3FF or any(flags & ~0x7F for _, _, flags in info["blocks"]):
        raise ValueError("writer_bundle_flags_unsupported")
    # Repacking must not discard unknown physical tails or normalise nonzero
    # padding. Parse metadata completely rather than accepting a valid prefix.
    with source.open("rb") as stream:
        bundle.cstring(stream, 32)
        bundle.number(stream, ">I")
        bundle.cstring(stream, 128)
        bundle.cstring(stream, 128)
        declared = bundle.number(stream, ">Q")
        compressed_meta = bundle.number(stream, ">I")
        uncompressed_meta = bundle.number(stream, ">I")
        flags = bundle.number(stream, ">I")
        prefix_end = (stream.tell() + 15) // 16 * 16
        metadata_start = declared - compressed_meta if flags & 0x80 else prefix_end
        data_end = info["data_start"] + sum(size for _, size, _ in info["blocks"])
        if data_end != (metadata_start if flags & 0x80 else declared):
            raise ValueError("writer_unexplained_physical_tail")
        pre_data = prefix_end if flags & 0x80 else prefix_end + compressed_meta
        stream.seek(pre_data)
        if any(bundle.exact(stream, info["data_start"] - pre_data)):
            raise ValueError("writer_nonzero_alignment_padding")
        stream.seek(metadata_start)
        import io
        metadata = io.BytesIO(decompress_block(bundle.exact(stream, compressed_meta), uncompressed_meta, flags))
        if any(bundle.exact(metadata, 16)):
            raise ValueError("writer_content_hash_not_supported")
        count = bundle.number(metadata, ">I")
        bundle.exact(metadata, 10 * count)
        nodes = bundle.number(metadata, ">I")
        for _ in range(nodes):
            bundle.exact(metadata, 20)
            bundle.cstring(metadata)
        if metadata.read(1):
            raise ValueError("writer_metadata_tail_unsupported")
    return info


def load_and_patch_serialized(serialized: Path, record, info):
    """Patch one AnimatorController and return a fixed-size receipt."""
    environment = UnityPy.load(str(serialized))
    try:
        matches = [obj for obj in environment.objects
                   if str(obj.path_id) == record["path_id"]
                   and getattr(obj.type, "name", "") == "AnimatorController"]
        if len(matches) != 1:
            raise ValueError("serialized_controller_not_unique")
        obj = matches[0]
        original = bytes(obj.get_raw_data())
        object_start = int(getattr(obj, "byte_start", -1))
        node_matches = [node for node in info["nodes"]
                        if node["offset"] <= object_start and
                        object_start + len(original) <= node["offset"] + node["size"] and
                        not (node["flags"] & 0x1)]
        if len(node_matches) != 1:
            raise ValueError("serialized_controller_node_invalid")
        node = node_matches[0]
        tree = obj.read_typetree()
        if not isinstance(tree, dict):
            raise ValueError("serialized_controller_unreadable")
        controller = unwrap(tree.get("m_Controller"))
        if not isinstance(controller, dict):
            raise ValueError("serialized_controller_shape_invalid")
        states = controller.get("m_StateMachineArray")
        if not isinstance(states, list) or record["machine_index"] >= len(states):
            raise ValueError("plan_machine_index_invalid")
        machine = unwrap(states[record["machine_index"]])
        if not isinstance(machine, dict):
            raise ValueError("serialized_machine_invalid")
        before = machine.get("m_DefaultState")
        if before != record["before"]:
            raise ValueError("serialized_before_mismatch")
        state_constants = machine.get("m_StateConstantArray")
        if not isinstance(state_constants, list) or record["unlock_state"] >= len(state_constants):
            raise ValueError("plan_unlock_state_invalid")
        machine["m_DefaultState"] = record["unlock_state"]
        replacement = bytes(obj.save_typetree(tree))
        if len(original) != len(replacement):
            raise ValueError("serialized_size_changed")
        differences = [i for i, (left, right) in enumerate(zip(original, replacement))
                       if left != right]
        if not differences or len(differences) > 4 or max(differences) - min(differences) >= 4:
            raise ValueError("serialized_delta_not_single_uint32")
        endian = getattr(obj.reader, "endian", "<")
        if endian not in ("<", ">"):
            raise ValueError("serialized_endian_invalid")
        candidates = [i for i in range(max(0, min(differences) - 3), min(differences) + 1)
                      if original[i:i + 4] == struct.pack(endian + "I", record["before"])
                      and replacement[i:i + 4] == struct.pack(endian + "I", record["unlock_state"])
                      and all(i <= changed < i + 4 for changed in differences)]
        if len(candidates) != 1:
            raise ValueError("serialized_delta_ambiguous")
        field = candidates[0]
        return {
            "controller_path_id": record["path_id"],
            "machine_index": record["machine_index"],
            "before": record["before"],
            "after": record["unlock_state"],
            "node_index": int(node["index"]),
            "object_offset": object_start,
            "field_offset": int(node["offset"]) + object_start + field,
            "field_offset_in_object": field,
            "endian": endian,
            "serialized_object_before_sha256": hashlib.sha256(original).hexdigest().upper(),
            "serialized_object_after_sha256": hashlib.sha256(replacement).hexdigest().upper(),
        }
    finally:
        del environment
        gc.collect()


def load_and_patch_pair(serialized: Path, records, info):
    """Resolve both fields from original object trees; serialize the pair once.

    Per-field serialization locates each uint32 independently. The final tree
    must equal exactly the union of those disjoint four-byte substitutions.
    No intermediate model or one-half result is ever written.
    """
    environment = UnityPy.load(str(serialized))
    fields = [None] * len(records)
    try:
        for path_id in dict.fromkeys(r["path_id"] for r in records):
            matches = [o for o in environment.objects if str(o.path_id) == path_id
                       and getattr(o.type, "name", "") == "AnimatorController"]
            if len(matches) != 1:
                raise ValueError("serialized_controller_not_unique")
            obj = matches[0]
            original = bytes(obj.get_raw_data())
            object_start = int(getattr(obj, "byte_start", -1))
            nodes = [n for n in info["nodes"] if n["flags"] == 4 and n["offset"] == 0
                     and n["offset"] <= object_start and object_start + len(original) <= n["size"]]
            if len(nodes) != 1:
                raise ValueError("serialized_controller_node_invalid")
            node = nodes[0]
            original_tree = obj.read_typetree()
            endian = getattr(obj.reader, "endian", "<")
            if endian not in ("<", ">"):
                raise ValueError("serialized_endian_invalid")

            def change(tree, record):
                controller = unwrap(tree.get("m_Controller")) if isinstance(tree, dict) else None
                states = controller.get("m_StateMachineArray") if isinstance(controller, dict) else None
                if not isinstance(states, list) or record["machine_index"] >= len(states):
                    raise ValueError("plan_machine_index_invalid")
                machine = unwrap(states[record["machine_index"]])
                if not isinstance(machine, dict) or machine.get("m_DefaultState") != record["before"]:
                    raise ValueError("serialized_before_mismatch")
                constants = machine.get("m_StateConstantArray")
                if not isinstance(constants, list) or max(record["before"], record["unlock_state"]) >= len(constants):
                    raise ValueError("plan_unlock_state_invalid")
                machine["m_DefaultState"] = record["unlock_state"]

            final_tree = copy.deepcopy(original_tree)
            expected = bytearray(original)
            owned = []
            for index, record in enumerate(records):
                if record["path_id"] != path_id:
                    continue
                one = copy.deepcopy(original_tree)
                change(one, record)
                replacement = bytes(obj.save_typetree(one))
                if len(replacement) != len(original):
                    raise ValueError("serialized_size_changed")
                delta = [i for i, (a, b) in enumerate(zip(original, replacement)) if a != b]
                if not delta or len(delta) > 4 or max(delta) - min(delta) >= 4:
                    raise ValueError("serialized_delta_not_single_uint32")
                before = struct.pack(endian + "I", record["before"])
                after = struct.pack(endian + "I", record["unlock_state"])
                starts = [i for i in range(max(0, min(delta) - 3), min(delta) + 1)
                          if original[i:i + 4] == before and replacement[i:i + 4] == after
                          and all(i <= d < i + 4 for d in delta)]
                if len(starts) != 1 or any(abs(starts[0] - start) < 4 for start in owned):
                    raise ValueError("serialized_pair_fields_ambiguous")
                field = starts[0]
                owned.append(field)
                expected[field:field + 4] = after
                change(final_tree, record)
                fields[index] = {
                    "controller_path_id": path_id, "controller": path_id,
                    "machine_index": record["machine_index"], "machine": record["machine_index"],
                    "before": record["before"], "after": record["unlock_state"],
                    "node_index": int(node["index"]), "object_offset": object_start,
                    "field_offset": object_start + field, "field_offset_in_object": field,
                    "endian": endian,
                }
            final_bytes = bytes(obj.save_typetree(final_tree))
            if final_bytes != bytes(expected):
                raise ValueError("serialized_pair_delta_mismatch")
            for field in fields:
                if field and field["controller_path_id"] == path_id:
                    field["serialized_object_before_sha256"] = hashlib.sha256(original).hexdigest().upper()
                    field["serialized_object_after_sha256"] = hashlib.sha256(final_bytes).hexdigest().upper()
        if any(field is None for field in fields):
            raise ValueError("serialized_pair_incomplete")
        return {"scope_kind": "dependent-state-pair", "fields": fields}
    finally:
        del environment
        gc.collect()


def compress_block(raw: bytes, flags: int, original_compressed: bytes) -> bytes:
    kind = flags & 63
    if kind == 0:
        return raw
    if kind in (2, 3):
        import lz4.block
        return lz4.block.compress(raw, mode="high_compression" if kind == 3 else "default",
                                  store_size=False)
    if kind == 1:
        if len(original_compressed) < 5:
            raise ValueError("lzma_header_missing")
        props, dictionary = struct.unpack("<BI", original_compressed[:5])
        if dictionary > 64 * 1024 * 1024:
            raise ValueError("lzma_dictionary_too_large")
        tail = lzma.compress(
            raw,
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dictionary,
                       "lc": props % 9, "lp": (props // 9) % 5,
                       "pb": props // 45}],
        )
        # Preserve the bundle's five-byte LZMA property header and generate a
        # fresh EOS stream for the modified block.  Verify the produced stream
        # has a real EOS and no physical trailing bytes before publishing it.
        encoded = original_compressed[:5] + tail
        props2, dictionary2 = struct.unpack("<BI", encoded[:5])
        decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dictionary2,
                       "lc": props2 % 9, "lp": (props2 // 9) % 5,
                       "pb": props2 // 45}],
        )
        restored = decoder.decompress(encoded[5:], max_length=len(raw) + 1)
        if not decoder.eof or decoder.unused_data or restored != raw:
            raise ValueError("lzma_eos_verification_failed")
        return encoded
    raise ValueError("unsupported_block_compression")


def decompress_block(data: bytes, size: int, flags: int) -> bytes:
    """Strict known-size input; new output encoding still requires EOS."""
    if flags & 63 != 1:
        return bundle.decompress(data, size, flags)
    return decompress_bytes(data, size)


_STREAM_CHUNK_BYTES = 4 * 1024 * 1024


def _lzma_filter_from_header(header: bytes):
    if len(header) != 5:
        raise ValueError("lzma_header_missing")
    props, dictionary = struct.unpack("<BI", header)
    if props >= 225:
        raise ValueError("lzma_properties_invalid")
    if dictionary > 64 * 1024 * 1024:
        raise ValueError("lzma_dictionary_too_large")
    return {
        "id": lzma.FILTER_LZMA1,
        "dict_size": dictionary,
        "lc": props % 9,
        "lp": (props // 9) % 5,
        "pb": props // 45,
    }


def _hash_expanded_chunk(raw: bytes, transformed: bytes, expanded_start: int,
                         nodes, old_hashes, new_hashes):
    expanded_end = expanded_start + len(raw)
    for node, old_hash, new_hash in zip(nodes, old_hashes, new_hashes):
        lo = max(expanded_start, node["offset"])
        hi = min(expanded_end, node["offset"] + node["size"])
        if lo < hi:
            old_hash.update(raw[lo - expanded_start:hi - expanded_start])
            new_hash.update(transformed[lo - expanded_start:hi - expanded_start])


def _verify_lzma_file(path: Path, expected_size: int):
    """Verify a physical LZMA block has one EOS and no trailing bytes."""
    with path.open("rb") as stream:
        header = bundle.exact(stream, 5)
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                         filters=[_lzma_filter_from_header(header)])
        remaining = path.stat().st_size - 5
        produced = 0
        pending = b""
        while not decoder.eof:
            if decoder.needs_input:
                if remaining <= 0:
                    raise ValueError("lzma_eos_truncated")
                pending = stream.read(min(_STREAM_CHUNK_BYTES, remaining))
                if not pending:
                    raise ValueError("lzma_eos_truncated")
                remaining -= len(pending)
            while True:
                out = decoder.decompress(pending, max_length=_STREAM_CHUNK_BYTES)
                pending = b""
                produced += len(out)
                if produced > expected_size:
                    raise ValueError("lzma_expanded_size_exceeded")
                if decoder.eof:
                    break
                if decoder.needs_input:
                    break
        if not decoder.eof or decoder.unused_data or remaining != 0:
            raise ValueError("lzma_eos_verification_failed")
        if produced != expected_size:
            raise ValueError("lzma_expanded_size_mismatch")


def _stream_lzma_block(stream, compressed_size: int, expanded_size: int,
                       block_path: Path, expanded_start: int, target_absolute,
                       patch, nodes, old_hashes, new_hashes):
    """Size-aware bounded input; all selected fields commit as one block."""
    header = bundle.exact(stream, 5)
    filters = [_lzma_filter_from_header(header)]
    rewrite = target_absolute is not None
    targets = patch["fields"] if rewrite and "fields" in patch else ([dict(patch, field_offset=target_absolute)] if rewrite else [])
    before = [struct.pack(p["endian"] + "I", p["before"]) for p in targets]
    after = [struct.pack(p["endian"] + "I", p["after"]) for p in targets]
    seen = [0 for _ in targets]
    produced = 0
    compressor = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filters) if rewrite else None
    with block_path.open("xb") as output_stream:
        if rewrite:
            output_stream.write(header)

        class BlockInput:
            def __init__(self):
                self.prefix = header
            def read(self, count):
                part = self.prefix[:count]
                self.prefix = self.prefix[len(part):]
                if len(part) < count:
                    part += stream.read(count - len(part))
                if not rewrite:
                    output_stream.write(part)
                return part

        for raw in iter_decode(BlockInput(), compressed_size, expanded_size, chunk_size=_STREAM_CHUNK_BYTES):
            chunk_start = expanded_start + produced
            transformed = bytearray(raw) if rewrite else raw
            if rewrite:
                chunk_end = chunk_start + len(raw)
                for index, target in enumerate(targets):
                    target_start = target["field_offset"]
                    for absolute in range(max(chunk_start, target_start), min(chunk_end, target_start + 4)):
                        local = absolute - chunk_start
                        byte_index = absolute - target_start
                        if raw[local] != before[index][byte_index]:
                            raise ValueError("bundle_before_bytes_mismatch")
                        transformed[local] = after[index][byte_index]
                        seen[index] |= 1 << byte_index
            transformed = bytes(transformed)
            _hash_expanded_chunk(raw, transformed, chunk_start, nodes, old_hashes, new_hashes)
            if rewrite:
                encoded = compressor.compress(transformed)
                if encoded:
                    output_stream.write(encoded)
            produced += len(raw)
        # Iterator exhaustion proves STREAM_END plus exact input/output.
        if produced != expanded_size:
            raise ValueError("lzma_expanded_size_mismatch")
        if rewrite:
            if any(mask != 0b1111 for mask in seen):
                raise ValueError("target_field_not_fully_decoded")
            output_stream.write(compressor.flush())
        output_stream.flush()
        os.fsync(output_stream.fileno())
    if rewrite:
        _verify_lzma_file(block_path, expanded_size)
    elif block_path.stat().st_size != compressed_size:
        raise ValueError("copied_lzma_size_mismatch")
    return block_path.stat().st_size


def repack(source: Path, output: Path, patch, source_sha256: str):
    if source.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("source_too_large")
    info = preflight_bundle(source)
    blocks = info["blocks"]
    fields = patch.get("fields") if patch.get("scope_kind") == "dependent-state-pair" else [patch]
    if not isinstance(fields, list) or len(fields) not in (1, 2) or ("fields" in patch and len(fields) != 2):
        raise ValueError("patch_scope_invalid")
    for field in fields:
        if (not isinstance(field, dict) or type(field.get("field_offset")) is not int or field["field_offset"] < 0 or
                field.get("endian") not in ("<", ">") or any(type(field.get(k)) is not int or not 0 <= field[k] <= 0xFFFFFFFF
                for k in ("before", "after")) or field["before"] == field["after"]):
            raise ValueError("patch_field_invalid")
    if any(i != j and abs(f["field_offset"] - g["field_offset"]) < 4
           for i, f in enumerate(fields) for j, g in enumerate(fields)):
        raise ValueError("patch_fields_overlap")
    absolute = fields[0]["field_offset"]
    nodes = info["nodes"]
    target_nodes = [node for node in nodes
                    if node["offset"] <= absolute < node["offset"] + node["size"]]
    if len(target_nodes) != 1 or target_nodes[0]["flags"] & 0x1:
        raise ValueError("target_not_in_serialized_node")
    if any(not target_nodes[0]["offset"] <= f["field_offset"] or
           f["field_offset"] + 4 > target_nodes[0]["offset"] + target_nodes[0]["size"] for f in fields):
        raise ValueError("target_not_in_serialized_node")

    # Read the fixed header and metadata exactly as stream_serialized_assets
    # does, then rewrite only the affected compressed block and its length.
    partial = output.with_name(output.name + ".partial")
    if (output.exists() or output.is_symlink() or partial.exists() or partial.is_symlink() or
            output.resolve() == source.resolve()):
        raise ValueError("refusing_output_overwrite")
    output.parent.mkdir(parents=True, exist_ok=True)
    partial_created = False
    pieces = []
    try:
        with tempfile.TemporaryDirectory(prefix=".vrca-writer-", dir=str(output.parent)) as temp_name:
            temp_dir = Path(temp_name)
            with source.open("rb") as stream:
                bundle.cstring(stream, 32)
                bundle.number(stream, ">I")
                bundle.cstring(stream, 128)
                bundle.cstring(stream, 128)
                fields_position = stream.tell()
                declared = bundle.number(stream, ">Q")
                compressed_meta = bundle.number(stream, ">I")
                uncompressed_meta = bundle.number(stream, ">I")
                header_flags = bundle.number(stream, ">I")
                prefix_end = (stream.tell() + 15) // 16 * 16
                stream.seek(0)
                prefix = bytearray(bundle.exact(stream, prefix_end))
                stream.seek(info["size"] - compressed_meta if header_flags & 0x80 else prefix_end)
                old_meta_compressed = bundle.exact(stream, compressed_meta)
                metadata = bytearray(decompress_block(old_meta_compressed, uncompressed_meta, header_flags))
                stream.seek(info["data_start"])
                position = 0
                old_hashes = [hashlib.sha256() for _ in nodes]
                new_hashes = [hashlib.sha256() for _ in nodes]
                for index, (size, compressed, flags) in enumerate(blocks):
                    if size > MAX_BLOCK_BYTES:
                        raise ValueError("expanded_block_too_large")
                    block_fields = [f for f in fields if position <= f["field_offset"] and f["field_offset"] + 4 <= position + size]
                    touched = bool(block_fields)
                    for f in fields:
                        if f["field_offset"] < position + size and f["field_offset"] + 4 > position and f not in block_fields:
                            raise ValueError("target_crosses_block")
                    block_path = temp_dir / f"block-{index:04d}.bin"
                    if (flags & 63) == 1:
                        packed_size = _stream_lzma_block(
                            stream, compressed, size, block_path, position,
                            block_fields[0]["field_offset"] if touched else None,
                            {"fields": block_fields} if touched else patch, nodes,
                            old_hashes, new_hashes)
                    else:
                        old_compressed = bundle.exact(stream, compressed)
                        original = decompress_block(old_compressed, size, flags)
                        if touched:
                            new_data = bytearray(original)
                            for field in block_fields:
                                relative = field["field_offset"] - position
                                expected_before = struct.pack(field["endian"] + "I", field["before"])
                                expected_after = struct.pack(field["endian"] + "I", field["after"])
                                if original[relative:relative + 4] != expected_before:
                                    raise ValueError("bundle_before_bytes_mismatch")
                                new_data[relative:relative + 4] = expected_after
                            new_data = bytes(new_data)
                            packed = compress_block(new_data, flags, old_compressed)
                        else:
                            new_data = original
                            packed = old_compressed
                        _hash_expanded_chunk(original, new_data, position, nodes,
                                             old_hashes, new_hashes)
                        with block_path.open("xb") as block_stream:
                            block_stream.write(packed)
                            block_stream.flush()
                            os.fsync(block_stream.fileno())
                        packed_size = len(packed)
                    pieces.append(block_path)
                    struct.pack_into(">I", metadata, 20 + 10 * index + 4, packed_size)
                    position += size

            old_digests = [item.hexdigest().upper() for item in old_hashes]
            new_digests = [item.hexdigest().upper() for item in new_hashes]
            target_index = target_nodes[0]["index"]
            if old_digests[target_index] == new_digests[target_index]:
                raise ValueError("serialized_node_did_not_change")
            for index, (old, new) in enumerate(zip(old_digests, new_digests)):
                if index != target_index and old != new:
                    raise ValueError("non_target_node_changed")

            new_meta = compress_block(bytes(metadata), header_flags, old_meta_compressed)
            payload_offset = len(prefix) + (0 if header_flags & 0x80 else len(new_meta))
            padding = b"\0" * ((-payload_offset) % 16 if header_flags & 0x200 else 0)
            total = (len(prefix) + len(padding) + sum(path.stat().st_size for path in pieces) +
                     len(new_meta))
            struct.pack_into(">QII", prefix, fields_position, total, len(new_meta), len(metadata))

            with partial.open("xb") as stream:
                partial_created = True
                stream.write(prefix)
                if not header_flags & 0x80:
                    stream.write(new_meta)
                stream.write(padding)
                for piece in pieces:
                    with piece.open("rb") as block_stream:
                        shutil.copyfileobj(block_stream, stream, length=_STREAM_CHUNK_BYTES)
                if header_flags & 0x80:
                    stream.write(new_meta)
                stream.flush()
                os.fsync(stream.fileno())
            verified = bundle.inspect(partial)
            if verified["nodes"] != info["nodes"] or verified["flags"] != info["flags"] or verified["engine"] != info["engine"]:
                raise ValueError("outer_bundle_identity_changed")
            if [(size, flags) for size, _, flags in verified["blocks"]] != [(size, flags) for size, _, flags in blocks]:
                raise ValueError("block_strategy_changed")
            if sha256_file(source) != source_sha256:
                raise ValueError("source_changed_during_write")
            # A hard-link publish is atomic and no-clobber on the same filesystem;
            # unlike os.replace it cannot overwrite an output created concurrently.
            if output.exists() or output.is_symlink():
                raise ValueError("output_created_during_write")
            os.link(partial, output)
            partial.unlink()
            partial_created = False
    except Exception:
        if partial_created:
            try:
                partial.unlink()
            except FileNotFoundError:
                pass
        raise

    return {
        "status": "written",
        "source_sha256": source_sha256,
        "output_sha256": sha256_file(output),
        "output_size": output.stat().st_size,
        **({"scope_kind": "dependent-state-pair", "fields": fields} if len(fields) == 2 else {
        "controller_path_id": patch["controller_path_id"],
        # Keep the receipt vocabulary accepted by the existing independent
        # proof while also retaining the explicit writer names above.
        "controller": patch["controller_path_id"],
        "machine_index": patch["machine_index"],
        "machine": patch["machine_index"],
        "before": patch["before"],
        "after": patch["after"],
        "field_offset": patch["field_offset"],
        "serialized_object_before_sha256": patch["serialized_object_before_sha256"],
        "serialized_object_after_sha256": patch["serialized_object_after_sha256"],
        }),
        "physical_changes": len(fields),
        "serialized_node_before_sha256": old_digests[target_index],
        "serialized_node_after_sha256": new_digests[target_index],
        "changed_node_index": target_index,
        "non_target_nodes_preserved": True,
        "atomic_output": True,
        "authorization_e2e": False,
    }


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--repack-only":
        if len(sys.argv) != 5:
            raise SystemExit("usage: --repack-only source patch.json output source_sha256")
        source = Path(sys.argv[2])
        patch = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
        output = Path(sys.argv[4])
        proof = repack(source, output, patch, patch["source_sha256"])
        print(json.dumps(proof, ensure_ascii=False, sort_keys=True))
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not args.source.is_file() or args.source.is_symlink():
        raise SystemExit("source_invalid")
    if args.source.stat().st_size > MAX_SOURCE_BYTES:
        raise SystemExit("source_too_large")
    source_sha = sha256_file(args.source)
    info = preflight_bundle(args.source)
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    record = validate_plan(plan, source_sha)
    patch = (load_and_patch_pair(args.source, record, info) if isinstance(record, list)
             else load_and_patch_serialized(args.source, record, info))
    patch["source_sha256"] = source_sha
    patch_path = args.output.with_name(args.output.name + ".writer.patch.json")
    if patch_path.exists() or patch_path.is_symlink():
        raise SystemExit("refusing_patch_descriptor_overwrite")
    patch_path.write_text(json.dumps(patch, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    try:
        # Keep the UnityPy object graph and the large serialized replacement in
        # a separate process from block recompression.  This bounds peak RSS
        # on Windows and mirrors the Linux process boundary used by staging.
        try:
            child = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--repack-only",
                 str(args.source), str(patch_path), str(args.output)],
                check=True, text=True, capture_output=True,
                env={**os.environ, "VRCA_UNLOCK_MEMORY_MB": "2048"},
            )
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip().splitlines()
            detail = detail[-1][:512] if detail else "child_exit_without_detail"
            raise ValueError(f"writer_repack_failed:{detail}") from exc
        lines = [line for line in child.stdout.splitlines() if line.strip()]
        if not lines:
            raise ValueError("writer_repack_no_proof")
        proof = json.loads(lines[-1])
    finally:
        try:
            patch_path.unlink()
        except FileNotFoundError:
            pass
    receipt = dict(proof)
    receipt["plan_sha256"] = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest().upper()
    args.output.with_suffix(args.output.suffix + ".writer.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"WRITER_REJECTED|{exc}", file=sys.stderr)
        raise SystemExit(2)

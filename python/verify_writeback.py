"""Independent read-only proof for a narrow state-only fixture output.

This deliberately does not import the licensed graph extractor or any writer.
It compares UnityPy object bytes and expanded UnityFS payload bytes, allowing
only the four-byte field named by the trusted local receipt.
"""
import hashlib
import json
import subprocess
import struct
import sys
import gc
import io
import lzma
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strict_lzma1ext import iter_decode
from unityfs_size_aware import install_bundle_reader, install_unitypy

import UnityPy

import stream_serialized_assets as bundle
install_bundle_reader(bundle)
install_unitypy()


def sha(data: bytes) -> str:
    if isinstance(data, (str, Path)):
        digest = hashlib.sha256()
        with Path(data).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest().upper()
    return hashlib.sha256(data).hexdigest().upper()


def object_snapshot(path: Path):
    env = UnityPy.load(str(path))
    result = {}
    for obj in env.objects:
        pid = str(obj.path_id)
        if pid in result:
            raise ValueError(f"duplicate path id: {pid}")
        result[pid] = (obj.type.name, obj.get_raw_data())
    del env
    gc.collect()
    return result


def child_snapshot(path: Path, destination: Path):
    subprocess.run([sys.executable, str(Path(__file__).resolve()), "--snapshot",
                    str(path), str(destination)], check=True)
    return json.loads(destination.read_text(encoding="utf-8"))


def child_target(path: Path, controller: str, machine: int, expected: int):
    subprocess.run([sys.executable, str(Path(__file__).resolve()), "--target",
                    str(path), controller, str(machine), str(expected)], check=True)


def receipt_aliases(receipt):
    """Normalize old and new narrow-writer receipt field names."""
    if receipt.get("physical_changes") == 2:
        if (type(receipt["physical_changes"]) is not int or receipt.get("scope_kind") != "dependent-state-pair" or
                not isinstance(receipt.get("fields"), list) or len(receipt["fields"]) != 2 or
                any(k in receipt for k in ("controller", "controller_path_id", "machine", "machine_index", "field_offset"))):
            raise ValueError("receipt dependency pair invalid")
        fields = []
        for field in receipt["fields"]:
            if not isinstance(field, dict) or "fields" in field or "physical_changes" in field:
                raise ValueError("receipt dependency pair invalid")
            fields.append(receipt_aliases(dict(field, physical_changes=1)))
        if len({(f["controller"], f["machine"]) for f in fields}) != 2 or abs(fields[0]["field_offset"] - fields[1]["field_offset"]) < 4:
            raise ValueError("receipt dependency pair overlap")
        receipt["fields"] = fields
        return receipt
    if "controller" in receipt and "controller_path_id" in receipt:
        if str(receipt["controller"]) != str(receipt["controller_path_id"]):
            raise ValueError("receipt controller aliases disagree")
    if "controller" not in receipt and "controller_path_id" in receipt:
        receipt["controller"] = receipt["controller_path_id"]
    if "machine" in receipt and "machine_index" in receipt:
        if receipt["machine"] != receipt["machine_index"]:
            raise ValueError("receipt machine aliases disagree")
    if "machine" not in receipt and "machine_index" in receipt:
        receipt["machine"] = receipt["machine_index"]
    required = ("physical_changes", "controller", "machine", "before",
                "after", "field_offset")
    if any(key not in receipt for key in required):
        raise ValueError("receipt missing narrow state fields")
    if type(receipt["physical_changes"]) is not int or receipt["physical_changes"] != 1:
        raise ValueError("receipt is not a single physical change")
    if type(receipt["machine"]) is not int or receipt["machine"] < 0:
        raise ValueError("receipt machine is invalid")
    if not isinstance(receipt["before"], int) or isinstance(receipt["before"], bool):
        raise ValueError("receipt before is not an integer")
    if not isinstance(receipt["after"], int) or isinstance(receipt["after"], bool):
        raise ValueError("receipt after is not an integer")
    if receipt["before"] == receipt["after"]:
        raise ValueError("receipt state is unchanged")
    if not (0 <= receipt["before"] <= 0xFFFFFFFF and 0 <= receipt["after"] <= 0xFFFFFFFF):
        raise ValueError("receipt state outside uint32")
    if type(receipt["field_offset"]) is not int or receipt["field_offset"] < 0:
        raise ValueError("receipt field offset invalid")
    return receipt


_PROOF_CHUNK_BYTES = 8 * 1024 * 1024
_PROOF_MAX_BLOCK_BYTES = 768 * 1024 * 1024


def _iter_lzma_raw(data_stream, compressed_size, expected_size):
    """Independent proof uses a shared format decoder, never writer logic."""
    if expected_size > _PROOF_MAX_BLOCK_BYTES:
        raise ValueError("proof block exceeds test-only bound")
    yield from iter_decode(data_stream, compressed_size, expected_size, chunk_size=_PROOF_CHUNK_BYTES)


def _iter_expanded(path: Path, info):
    """Yield each expanded UnityFS block in bounded pieces."""
    with path.open("rb") as stream:
        stream.seek(info["data_start"])
        for size, compressed, flags in info["blocks"]:
            if size > _PROOF_MAX_BLOCK_BYTES:
                raise ValueError("proof block exceeds test-only bound")
            kind = flags & 63
            if kind == 1:
                yield from _iter_lzma_raw(stream, compressed, size)
                continue
            # The current fixture is LZMA.  Keep other kinds bounded and
            # explicit so this proof cannot silently become a generic writer.
            data = bundle.exact(stream, compressed)
            if kind == 0:
                if len(data) != size:
                    raise ValueError("uncompressed block size mismatch")
                for start in range(0, len(data), _PROOF_CHUNK_BYTES):
                    yield data[start:start + _PROOF_CHUNK_BYTES]
            elif kind in (2, 3):
                out = bundle.decompress(data, size, flags)
                for start in range(0, len(out), _PROOF_CHUNK_BYTES):
                    yield out[start:start + _PROOF_CHUNK_BYTES]
            else:
                raise ValueError(f"unsupported proof compression kind: {kind}")


def _window_bytes(path: Path, info, start: int, end: int):
    cursor = 0
    out = bytearray()
    for chunk in _iter_expanded(path, info):
        chunk_end = cursor + len(chunk)
        lo = max(start, cursor)
        hi = min(end, chunk_end)
        if hi > lo:
            out.extend(chunk[lo - cursor:hi - cursor])
        cursor = chunk_end
        if cursor >= end:
            break
    return bytes(out)


def _compressed_hash(stream, size):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = stream.read(min(_PROOF_CHUNK_BYTES, remaining))
        if not chunk:
            raise ValueError("truncated compressed proof block")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.digest()


def _require_physical_eos(stream, compressed_size, expected_size):
    """Independently require EOS on a newly compressed output block.

    Known-size source compatibility must not weaken the writer's output
    format. This verifier is deliberately not imported from the writer.
    """
    if compressed_size < 5 or not 0 <= expected_size <= _PROOF_MAX_BLOCK_BYTES:
        raise ValueError("new LZMA output size invalid")
    props, dictionary = struct.unpack("<BI", bundle.exact(stream, 5))
    if props >= 225 or dictionary > 64 * 1024 * 1024:
        raise ValueError("new LZMA output properties invalid")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "dict_size": dictionary,
        "lc": props % 9, "lp": (props // 9) % 5, "pb": props // 45,
    }])
    remaining = compressed_size - 5
    produced = 0
    while not decoder.eof:
        pending = b""
        if decoder.needs_input:
            if remaining == 0:
                raise ValueError("new LZMA output has no physical EOS")
            pending = stream.read(min(_PROOF_CHUNK_BYTES, remaining))
            if not pending:
                raise ValueError("new LZMA output truncated")
            remaining -= len(pending)
        out = decoder.decompress(pending, max_length=_PROOF_CHUNK_BYTES)
        produced += len(out)
        if produced > expected_size:
            raise ValueError("new LZMA output exceeds declared size")
    if remaining != 0 or decoder.unused_data or produced != expected_size:
        raise ValueError("new LZMA output EOS or exact size mismatch")


def _metadata_compression(path):
    with path.open("rb") as stream:
        bundle.cstring(stream, 32)
        bundle.number(stream, ">I")
        bundle.cstring(stream, 128)
        bundle.cstring(stream, 128)
        declared = bundle.number(stream, ">Q")
        compressed, expanded, flags = (bundle.number(stream, ">I") for _ in range(3))
        start = declared - compressed if flags & 0x80 else (stream.tell() + 15) // 16 * 16
        return start, compressed, expanded, flags


def verify_output_compression(source, output, before_info, after_info, fields):
    """Untouched blocks stay byte-identical; new LZMA data/metadata use EOS."""
    if len(before_info["blocks"]) != len(after_info["blocks"]):
        raise ValueError("output block count changed")
    with source.open("rb") as left, output.open("rb") as right:
        left.seek(before_info["data_start"])
        right.seek(after_info["data_start"])
        expanded_at = 0
        for old, new in zip(before_info["blocks"], after_info["blocks"]):
            if (old[0], old[2]) != (new[0], new[2]):
                raise ValueError("output block shape changed")
            output_start = right.tell()
            left_hash = _compressed_hash(left, old[1])
            right_hash = _compressed_hash(right, new[1])
            touched = any(expanded_at <= f["field_offset"] and f["field_offset"] + 4 <= expanded_at + old[0] for f in fields)
            if not touched and (old[1] != new[1] or left_hash != right_hash):
                raise ValueError("untouched compressed block changed")
            if touched and new[2] & 63 == 1:
                right.seek(output_start)
                _require_physical_eos(right, new[1], new[0])
            expanded_at += old[0]
        old_start, old_size, _, _ = _metadata_compression(source)
        new_start, new_size, new_expanded, new_flags = _metadata_compression(output)
        left.seek(old_start)
        right.seek(new_start)
        old_hash = _compressed_hash(left, old_size)
        new_hash = _compressed_hash(right, new_size)
        if new_flags & 63 == 1 and (old_size != new_size or old_hash != new_hash):
            right.seek(new_start)
            _require_physical_eos(right, new_size, new_expanded)


def compare_expanded(source: Path, output: Path, field_offset: int, before: int, after: int):
    """Compare expanded payloads with a four-byte allow-list, streaming."""
    return compare_expanded_fields(source, output, [{"field_offset": field_offset, "before": before, "after": after}])


def compare_expanded_fields(source: Path, output: Path, fields):
    """Independently compare every byte against one or two disjoint windows."""
    if not isinstance(fields, list) or len(fields) not in (1, 2):
        raise ValueError("proof field count invalid")
    for f in fields:
        if (type(f.get("field_offset")) is not int or f["field_offset"] < 0 or
                any(type(f.get(k)) is not int or not 0 <= f[k] <= 0xFFFFFFFF for k in ("before", "after")) or
                f["before"] == f["after"]):
            raise ValueError("proof field invalid")
    if any(i != j and abs(f["field_offset"] - g["field_offset"]) < 4 for i, f in enumerate(fields) for j, g in enumerate(fields)):
        raise ValueError("proof fields overlap")
    before_info = bundle.inspect(source)
    after_info = bundle.inspect(output)
    if before_info["expanded_size"] != after_info["expanded_size"]:
        raise ValueError("expanded payload length changed")
    if before_info["blocks"] != [(a, b, c) for a, b, c in after_info["blocks"]]:
        # Compressed lengths may change after re-encoding; only expanded block
        # sizes and flags are structural invariants for this proof.
        before_shape = [(a, c) for a, b, c in before_info["blocks"]]
        after_shape = [(a, c) for a, b, c in after_info["blocks"]]
        if before_shape != after_shape:
            raise ValueError("expanded block sizes/flags changed")
    windows = [(f["field_offset"], f["field_offset"] + 4) for f in fields]
    deltas = []
    offset = 0
    left_iter = iter(_iter_expanded(source, before_info))
    right_iter = iter(_iter_expanded(output, after_info))
    left = next(left_iter, None)
    right = next(right_iter, None)
    while left is not None or right is not None:
        if left is None or right is None:
            raise ValueError("expanded stream lengths differ")
        take = min(len(left), len(right))
        # Bulk equality checks all bytes in C; inspect only a differing chunk
        # byte by byte. This does not weaken the four-byte allow-list.
        if left[:take] != right[:take]:
            for index, (a, b) in enumerate(zip(left[:take], right[:take])):
                position = offset + index
                if a != b:
                    if not any(start <= position < end for start, end in windows):
                        raise ValueError(f"unexpected expanded payload delta at {position}")
                    deltas.append(position)
        left = left[take:]
        right = right[take:]
        if not left:
            left = next(left_iter, None)
        if not right:
            right = next(right_iter, None)
        offset += take
    if any(not any(start <= position < end for start, end in windows) for position in deltas):
        raise ValueError(f"unexpected changed byte outside allow-list: {deltas}")
    # A numeric state change may leave leading zero bytes identical (for
    # example 0 -> 264), so the allow-list is a four-byte window rather than a
    # requirement that all four positions differ.
    for field, (start, end) in zip(fields, windows):
        before, after = field["before"], field["after"]
        source_window = _window_bytes(source, before_info, start, end)
        output_window = _window_bytes(output, after_info, start, end)
        if not any(start <= changed < end for changed in deltas):
            raise ValueError("target field did not change")
        if source_window not in (struct.pack(">I", before), struct.pack("<I", before)):
            raise ValueError("source bytes do not encode the receipt before state")
        encodings = [encoding for encoding in (">", "<") if output_window == struct.pack(encoding + "I", after)]
        if len(encodings) != 1:
            raise ValueError("target bytes do not encode the requested state unambiguously")
        if source_window != struct.pack(encodings[0] + "I", before):
            raise ValueError("source/target serialized endianness differs")
    verify_output_compression(source, output, before_info, after_info, fields)
    return before_info, after_info, deltas


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--snapshot":
        snapshot = object_snapshot(Path(sys.argv[2]))
        Path(sys.argv[3]).write_text(
            json.dumps({key: [value[0], sha(value[1])] for key, value in snapshot.items()},
                       sort_keys=True), encoding="utf-8")
        return 0
    if len(sys.argv) >= 2 and sys.argv[1] == "--target":
        env = UnityPy.load(sys.argv[2])
        target = next(obj for obj in env.objects if str(obj.path_id) == sys.argv[3])
        tree = target.read_typetree()
        machine = tree["m_Controller"]["m_StateMachineArray"][int(sys.argv[4])]
        value = machine.get("data", machine).get("m_DefaultState")
        if value != int(sys.argv[5]):
            raise ValueError(f"target default state mismatch: {value}")
        return 0
    if len(sys.argv) != 4:
        raise SystemExit("usage: test_independent_reparse.py source.vrca output.vrca receipt.json")
    source, output, receipt_path = map(Path, sys.argv[1:])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt = receipt_aliases(receipt)
    if source.resolve() == output.resolve() or not source.is_file() or not output.is_file():
        raise ValueError("source/output path invalid")
    if receipt.get("source_sha256") != sha(source):
        raise ValueError("source receipt hash mismatch")
    if receipt.get("output_sha256") != sha(output):
        raise ValueError("output receipt hash mismatch")
    fields = receipt["fields"] if receipt["physical_changes"] == 2 else [receipt]
    controllers = sorted({str(f["controller"]) for f in fields})
    work = receipt_path.parent / ".independent-reparse-work"
    work.mkdir(exist_ok=True)
    before_objects = child_snapshot(source, work / "source-objects.json")
    after_objects = child_snapshot(output, work / "output-objects.json")
    if set(before_objects) != set(after_objects):
        raise ValueError("object path-id set changed")
    changed = []
    for pid in sorted(before_objects):
        before_type, before_hash = before_objects[pid]
        after_type, after_hash = after_objects[pid]
        if before_type != after_type:
            raise ValueError(f"object type changed: {pid}")
        if before_hash != after_hash:
            changed.append(pid)
    if changed != controllers:
        raise ValueError(f"unexpected changed objects: {changed}")
    for field in fields:
        controller = str(field["controller"])
        if field.get("serialized_object_before_sha256") not in (None, before_objects[controller][1]):
            raise ValueError("source object receipt hash mismatch")
        if field.get("serialized_object_after_sha256") not in (None, after_objects[controller][1]):
            raise ValueError("output object receipt hash mismatch")
        child_target(source, controller, int(field["machine"]), int(field["before"]))
        child_target(output, controller, int(field["machine"]), int(field["after"]))
    before_info = bundle.inspect(source)
    after_info = bundle.inspect(output)
    if any(before_info[key] != after_info[key] for key in ("engine", "player", "version", "flags")):
        raise ValueError("UnityFS identity changed")
    if before_info["nodes"] != after_info["nodes"]:
        raise ValueError("UnityFS node directory changed")
    _, _, delta = compare_expanded_fields(source, output, fields)
    result = {
        "status": "passed",
        "source_sha256": sha(source),
        "output_sha256": sha(output),
        "objects": len(before_objects),
        "changed_objects": changed,
        "changed_expanded_bytes": delta,
        "physical_changes": len(fields),
        "unityfs_nodes_preserved": True,
        "resource_and_non_target_bytes_preserved": True,
        "authorization_e2e": False,
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

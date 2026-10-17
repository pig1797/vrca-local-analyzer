"""Strict known-size raw LZMA1 input, backed by an official-header C shim.

No output encoding or fallback. A generator is verified only once exhausted;
callers must stage any writes and must never commit on early iterator exit.
Native/format failure is explicit. MemoryError and OSError are not swallowed.
"""
from __future__ import annotations

import ctypes as ct
import io
import os
from pathlib import Path
import sys
import threading

MAX_DICTIONARY_BYTES = 64 * 1024 * 1024
MAX_BLOCK_BYTES = 768 * 1024 * 1024
MAX_CHUNK_BYTES = 8 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024
# liblzma's optional-EOPM known-size state may not survive EOPM split across
# input calls (reproduced with 5.8.3). Its official LZMA_IN_REQUIRED is 20,
# plus one final normalisation byte. Keep 64 final payload bytes together,
# without discarding anything or changing exact STREAM_END acceptance.
_END_LOOKAHEAD_BYTES = 64
_library = None
_library_lock = threading.Lock()


class LzmaFormatError(ValueError):
    """Input isn't one complete bounded stream of the declared exact size."""


def _bounded_int(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise LzmaFormatError("invalid_" + name)


def _check_code(code, phase):
    if code == 5:
        raise MemoryError("lzma_native_memory_error")
    if code not in (0, 1):
        raise LzmaFormatError("lzma_" + phase + "_failed_" + str(code))


def _lib():
    global _library
    if _library is not None:
        return _library
    with _library_lock:
        if _library is not None:
            return _library
        default = "vrca_lzma1ext.dll" if sys.platform == "win32" else "libvrca_lzma1ext.so"
        location = Path(__file__).resolve().parent.parent / "bin" / default
        if not location.is_absolute():
            raise LzmaFormatError("native_library_path_must_be_absolute")
        native = ct.CDLL(str(location))
        native.vrca_lzma_init.argtypes = [ct.c_wchar_p]
        native.vrca_lzma_init.restype = ct.c_int
        native.vrca_lzma_runtime_version.argtypes = []
        native.vrca_lzma_runtime_version.restype = ct.c_char_p
        native.vrca_lzma_contract_version.argtypes = []
        native.vrca_lzma_contract_version.restype = ct.c_uint32
        native.vrca_lzma_open.argtypes = [ct.c_void_p, ct.c_size_t, ct.c_uint64,
                                        ct.c_uint64, ct.POINTER(ct.c_void_p)]
        native.vrca_lzma_open.restype = ct.c_int
        native.vrca_lzma_feed.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_size_t,
            ct.c_void_p, ct.c_size_t, ct.c_int, ct.POINTER(ct.c_size_t),
            ct.POINTER(ct.c_size_t), ct.POINTER(ct.c_uint64), ct.POINTER(ct.c_uint64)]
        native.vrca_lzma_feed.restype = ct.c_int
        native.vrca_lzma_close.argtypes = [ct.c_void_p]
        native.vrca_lzma_close.restype = None
        runtime = None
        if sys.platform == "win32":
            runtime = str(Path(__file__).resolve().parent.parent / "bin" / "liblzma-5.dll")
            if not Path(runtime).is_absolute():
                raise LzmaFormatError("lzma_runtime_path_must_be_absolute")
        _check_code(native.vrca_lzma_init(runtime), "initialize")
        if native.vrca_lzma_contract_version() != 1:
            raise LzmaFormatError("lzma_native_contract_mismatch")
        _library = native
        return native


def runtime_version():
    return _lib().vrca_lzma_runtime_version().decode("ascii", "strict")


def _read(stream, count):
    block = stream.read(count)
    if not isinstance(block, bytes) or len(block) > count:
        raise LzmaFormatError("invalid_stream_read")
    return block


def _properties(stream):
    parts = []
    remaining = 5
    while remaining:
        piece = _read(stream, remaining)
        if not piece:
            raise LzmaFormatError("truncated_lzma_properties")
        parts.append(piece)
        remaining -= len(piece)
    props = b"".join(parts)
    prop = props[0]
    dictionary = int.from_bytes(props[1:], "little")
    if prop >= 225 or prop % 9 + (prop // 9) % 5 > 4 or dictionary > MAX_DICTIONARY_BYTES:
        raise LzmaFormatError("invalid_lzma_properties")
    return props


def iter_decode(stream, compressed_size, expected_size, chunk_size=DEFAULT_CHUNK_BYTES):
    """Yield exact block content from a stream currently at its five-byte props.

    compressed_size includes the props, but not any following UnityFS block.
    Reads never cross that boundary. EOS may be present only at the exact end.
    Trailing/concatenated input, early end, truncation and incorrect sizes fail.
    Reads/yields are bounded by chunk_size (<=8MiB). The last native input
    feed may be 64 bytes even when a smaller chunk_size was requested.
    """
    _bounded_int(compressed_size, 10, MAX_BLOCK_BYTES + 5, "compressed_size")
    _bounded_int(expected_size, 0, MAX_BLOCK_BYTES, "expected_size")
    _bounded_int(chunk_size, 1, MAX_CHUNK_BYTES, "chunk_size")
    props = _properties(stream)
    native = _lib()
    context = ct.c_void_p()
    _check_code(native.vrca_lzma_open(props, len(props), compressed_size - 5,
                                   expected_size, ct.byref(context)), "open")
    if not context.value:
        raise LzmaFormatError("lzma_context_missing")
    try:
        out = ct.create_string_buffer(chunk_size)
        left = compressed_size - 5
        pending = b""
        consumed = ct.c_size_t()
        produced = ct.c_size_t()
        total_in = ct.c_uint64()
        total_out = ct.c_uint64()
        stall = 0
        while True:
            if not pending and left:
                if left <= _END_LOOKAHEAD_BYTES:
                    final_parts = []
                    while left:
                        piece = _read(stream, min(chunk_size, left))
                        if not piece:
                            raise LzmaFormatError("truncated_lzma_payload")
                        final_parts.append(piece)
                        left -= len(piece)
                    pending = b"".join(final_parts)
                else:
                    pending = _read(stream, min(chunk_size, left - _END_LOOKAHEAD_BYTES))
                    if not pending:
                        raise LzmaFormatError("truncated_lzma_payload")
                    left -= len(pending)
            code = native.vrca_lzma_feed(context, pending, len(pending), out,
                len(out), int(left == 0), ct.byref(consumed), ct.byref(produced),
                ct.byref(total_in), ct.byref(total_out))
            _check_code(code, "decode")
            if consumed.value > len(pending) or produced.value > chunk_size:
                raise LzmaFormatError("native_counter_contract")
            pending = pending[consumed.value:]
            if total_in.value > compressed_size - 5 or total_out.value > expected_size:
                raise LzmaFormatError("lzma_total_outside_declared_bounds")
            if produced.value:
                yield out.raw[:produced.value]
            if code == 1:
                if (left != 0 or pending or total_in.value != compressed_size - 5
                        or total_out.value != expected_size):
                    raise LzmaFormatError("lzma_exact_boundary_mismatch")
                return
            if not consumed.value and not produced.value:
                stall += 1
                if stall > 1:
                    raise LzmaFormatError("lzma_decoder_stalled")
            else:
                stall = 0
    finally:
        native.vrca_lzma_close(context)


def decompress_bytes(data, expected_size):
    """UnityPy bytes API: return content only after full strict validation.

    This API necessarily materialises one output block for the UnityPy caller.
    Writers/byte-proof consumers should instead use iter_decode's bounded path.
    """
    if not isinstance(data, bytes):
        if not isinstance(data, (bytearray, memoryview)):
            raise LzmaFormatError("invalid_compressed_buffer")
        data = bytes(data)
    return b"".join(iter_decode(io.BytesIO(data), len(data), expected_size))

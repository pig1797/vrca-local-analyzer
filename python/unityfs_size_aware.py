"""Process-local, format-only size-aware UnityFS LZMA readers.

This module knows nothing about plans, objects, authorization or writeback.
Only UnityFS's compression map is replaced; UnityPy's legacy UnityWeb/TPK
decompress_lzma API, all other compression codecs and frozen files stay intact.
"""
from __future__ import annotations

from strict_lzma1ext import decompress_bytes


_unitypy_original = None


def _unityfs_lzma(compressed_data, declared_size):
    return decompress_bytes(compressed_data, declared_size)


def install_unitypy():
    """Install just the known-size UnityFS LZMA map entry, idempotently."""
    from UnityPy.enums import CompressionFlags
    from UnityPy.helpers import CompressionHelper

    global _unitypy_original
    mapping = CompressionHelper.DECOMPRESSION_MAP
    current = mapping[CompressionFlags.LZMA]
    if current is _unityfs_lzma:
        return
    if _unitypy_original is not None:
        raise RuntimeError("unityfs_lzma_mapper_changed_after_install")
    _unitypy_original = current
    mapping[CompressionFlags.LZMA] = _unityfs_lzma


def install_bundle_reader(reader):
    """Keep a caller's existing probe bounds and non-LZMA reader unchanged."""
    original = reader.decompress
    if getattr(original, "_vrca_size_aware_lzma", False):
        return

    def decode(data, size, flags):
        if flags & 63 != 1:
            return original(data, size, flags)
        if type(size) is not int or not 0 <= size <= reader.MAX_BLOCK_BYTES:
            raise ValueError("single block exceeds safe probe limit")
        return decompress_bytes(data, size)

    decode._vrca_size_aware_lzma = True
    reader.decompress = decode

"""Cross-platform synthetic boundary tests; never reads any customer/model file."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "python"))
import strict_lzma1ext as strict
import base64


def raw_recipe(name):
    return {
        "empty": lambda: b"",
        "single": lambda: b"x",
        "short": lambda: b"one strict known size block",
        "pattern": lambda: bytes(range(256)) * 64 + b"final!",
        "stream": lambda: b"stream bounded LZMA input bytes." * 131072,
    }[name]()


FIXTURES = json.loads((ROOT / "lzma-synthetic-fixtures.json").read_text("utf-8"))["fixtures"]


def compressed(fixture):
    return base64.b64decode(fixture["compressedBase64"], validate=True)


class CappedRead(io.BytesIO):
    def __init__(self, data, cap):
        super().__init__(data)
        self.cap = cap
        self.maximum_requested = 0
        self.read_calls = 0

    def read(self, count=-1):
        if count < 0:
            raise AssertionError("unbounded_read")
        self.maximum_requested = max(self.maximum_requested, count)
        self.read_calls += 1
        return super().read(min(count, self.cap))


class Boundaries(unittest.TestCase):
    assertions = 0

    def checked(self, condition, message="boundary check"):
        type(self).assertions += 1
        self.assertTrue(condition, message)

    def reject(self, data, expected, *, chunk=31):
        type(self).assertions += 1
        with self.assertRaises(strict.LzmaFormatError):
            list(strict.iter_decode(io.BytesIO(data), len(data), expected, chunk))

    def test_runtime(self):
        self.checked(bool(strict.runtime_version()))

    def test_valid_eos_and_known_size_no_eos(self):
        for fixture in FIXTURES:
            data, raw = compressed(fixture), raw_recipe(fixture["recipe"])
            self.checked(hashlib.sha256(raw).hexdigest() == fixture["rawSha256"])
            sizes = (1, 7, 31, 4096) if len(raw) < 32768 else (65536, 1048576)
            for chunk_size in sizes:
                with self.subTest(recipe=fixture["recipe"], eos=fixture["eopm"], chunk=chunk_size):
                    output = list(strict.iter_decode(io.BytesIO(data), len(data), len(raw), chunk_size))
                    self.checked(b"".join(output) == raw)
                    self.checked(all(0 < len(part) <= chunk_size for part in output))
            self.checked(strict.decompress_bytes(data, len(raw)) == raw)

    def test_malformed_boundaries(self):
        for fixture in FIXTURES:
            if fixture["recipe"] == "stream":
                continue
            data, size = compressed(fixture), fixture["size"]
            for tail in (b"\0", b"\xff", data, b"non-stream-tail"):
                self.reject(data + tail, size)
            for removed in sorted(set((1, 2, 3, 4, 5, 8, len(data) // 2))):
                self.reject(data[:-removed], size)
            if size:
                self.reject(data, size - 1)
            self.reject(data, size + 1)
            # Canonical range termination is significant, not just output length.
            self.reject(data[:-1] + bytes([data[-1] ^ 0x80]), size)

    def test_properties_and_limits(self):
        data = compressed(FIXTURES[4])
        size = FIXTURES[4]["size"]
        self.reject(b"\xff" + data[1:], size)
        # props 44 => lc8/lp4/pb0, unsupported lc+lp.
        self.reject(bytes([44]) + data[1:], size)
        self.reject(data[:1] + struct.pack("<I", strict.MAX_DICTIONARY_BYTES + 1) + data[5:], size)
        for expected in (-1, True, False, None, "1", 1.0, strict.MAX_BLOCK_BYTES + 1):
            self.reject(data, expected)
        for chunk in (0, -1, True, "1", strict.MAX_CHUNK_BYTES + 1):
            self.reject(data, size, chunk=chunk)
        for length in (-1, 0, 5, 9, True, strict.MAX_BLOCK_BYTES + 6):
            type(self).assertions += 1
            with self.assertRaises(strict.LzmaFormatError):
                list(strict.iter_decode(io.BytesIO(data), length, size))
        for value in (None, "text", 12):
            type(self).assertions += 1
            with self.assertRaises(strict.LzmaFormatError):
                strict.decompress_bytes(value, size)

    def test_input_and_output_are_chunk_bounded(self):
        for fixture in FIXTURES[-2:]:
            data, raw = compressed(fixture), raw_recipe(fixture["recipe"])
            source = CappedRead(data, 37)
            digest = hashlib.sha256()
            total = maximum = 0
            for part in strict.iter_decode(source, len(data), len(raw), 8191):
                total += len(part)
                maximum = max(maximum, len(part))
                digest.update(part)
            self.checked(digest.hexdigest() == fixture["rawSha256"])
            self.checked(total == len(raw))
            self.checked(maximum <= 8191)
            self.checked(source.maximum_requested <= 8191)
            self.checked(source.read_calls > 1)

    def test_all_short_read_tail_splits(self):
        for fixture in FIXTURES[4:6]:
            data, raw = compressed(fixture), raw_recipe(fixture["recipe"])
            for cap in range(1, len(data) + 2):
                for chunk in (1, 7, 63, 64, 65):
                    source = CappedRead(data, cap)
                    output = b"".join(strict.iter_decode(source, len(data), len(raw), chunk))
                    self.checked(output == raw)
                    self.checked(source.tell() == len(data))

    def test_other_valid_properties(self):
        raw = bytes(range(251)) * 19 + b"properties-boundary"
        for lc, lp, pb in ((0, 0, 0), (4, 0, 4), (1, 3, 2), (3, 1, 0)):
            props = struct.pack("<BI", (pb * 5 + lp) * 9 + lc, 4096)
            payload = lzma.compress(raw, format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 4096,
                          "lc": lc, "lp": lp, "pb": pb}])
            for chunk in (1, 13, 65, 4096):
                output = b"".join(strict.iter_decode(io.BytesIO(props + payload),
                    len(props) + len(payload), len(raw), chunk))
                self.checked(output == raw)

    def test_adjacent_block_not_consumed(self):
        for fixture in FIXTURES:
            data, raw = compressed(fixture), raw_recipe(fixture["recipe"])
            marker = b"next-unityfs-block-not-part-of-this-input"
            source = CappedRead(data + marker, 3)
            output = b"".join(strict.iter_decode(source, len(data), len(raw), 65536))
            self.checked(output == raw)
            self.checked(source.tell() == len(data))
            self.checked(io.BytesIO.read(source) == marker)

    def test_io_and_memory_errors_not_swallowed(self):
        fixture = FIXTURES[4]
        data = compressed(fixture)
        for error in (OSError("synthetic_io_error"), MemoryError("synthetic_memory_error")):
            for fail_after in (0, 5):
                class FailingStream(io.BytesIO):
                    def read(self, count=-1):
                        if self.tell() >= fail_after:
                            raise error
                        return super().read(count)
                type(self).assertions += 1
                with self.assertRaises(type(error)) as seen:
                    list(strict.iter_decode(FailingStream(data), len(data), fixture["size"]))
                self.checked(seen.exception is error)
        type(self).assertions += 1
        with self.assertRaises(MemoryError):
            strict._check_code(5, "synthetic_allocator")

    def test_absent_native_does_not_fallback(self):
        # The packaged library path is fixed, not chosen through environment.
        script = "import sys;sys.path.insert(0,sys.argv[1]);import strict_lzma1ext as s;s.__file__=str(s.Path(sys.argv[2])/'missing'/'codec.py');s.runtime_version()"
        process = subprocess.run([sys.executable, "-c", script, str(ROOT.parent / "python"), str(ROOT)],
                                 capture_output=True, timeout=10)
        self.checked(process.returncode != 0)
        self.checked(b"OSError" in process.stderr or b"FileNotFoundError" in process.stderr)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Boundaries)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("STRICT_LZMA1EXT_TESTS|assertions=%d|cases=%d|ok=%s|syntheticOnly=true|runtime=%s" %
          (Boundaries.assertions, result.testsRun, result.wasSuccessful(), strict.runtime_version()))
    raise SystemExit(0 if result.wasSuccessful() else 1)

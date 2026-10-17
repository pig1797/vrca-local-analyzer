"""Build a new portable folder from explicit trusted inputs; never overwrite.

Requires 64-bit CPython 3.12 + pip, official 3.12 embeddable ZIP, an audited
wheelhouse and a locally built MSVC worker. No developer environment is copied.
"""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-zip", required=True, type=Path)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--launcher", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--codec", required=True, type=Path)
    parser.add_argument("--lzma-runtime", required=True, type=Path)
    parser.add_argument("--lzma-sha256", required=True)
    parser.add_argument("--exporter-zip", required=True, type=Path)
    parser.add_argument("--sdk-root", required=True, type=Path)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error("Build with CPython 3.12 for the pinned Windows wheels.")
    if digest(args.python_zip) != args.python_sha256.lower():
        parser.error("Python ZIP SHA256 mismatch.")
    if digest(args.lzma_runtime) != args.lzma_sha256.lower():
        parser.error("liblzma SHA256 mismatch.")
    if digest(args.exporter_zip) != "9a7ef0e7c5c3ea5b90b4e6d855e2d98d5f7ec8c3f9e26fccbc194c6a7b01baf7":
        parser.error("Expected the official AssetRipper 2.0.0 Windows x64 archive.")
    for name in ("com.vrchat.base", "com.vrchat.avatars"):
        sdk = args.sdk_root / name
        metadata = json.loads((sdk / "package.json").read_text(encoding="utf-8"))
        if metadata["name"] != name or metadata["version"] != "3.10.4" or not (sdk / "license.txt").is_file():
            parser.error("SDK 3.10.4 packages and their own licence files are required.")
        if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in sdk.rglob("*")):
            parser.error("SDK links are forbidden.")
    if args.output.exists():
        parser.error("Output exists; choose a new directory (nothing was overwritten).")
    args.output.mkdir(parents=True)
    runtime = args.output / "runtime"
    runtime.mkdir()
    with zipfile.ZipFile(args.python_zip) as archive:
        for name in archive.namelist():
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or ":" in name or "\\" in name:
                raise ValueError("Unsafe Python archive entry.")
        archive.extractall(runtime)
    # Retain the official runtime license and its bundled component notices.
    if not (runtime / "LICENSE.txt").is_file() or not (runtime / "python312.zip").is_file():
        raise ValueError("Not a CPython 3.12 embeddable distribution.")
    (runtime / "python312._pth").write_text("python312.zip\n.\nLib/site-packages\n..\nimport site\n", encoding="ascii")
    site = runtime / "Lib" / "site-packages"
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--only-binary=:all:",
        "--find-links", str(args.wheelhouse.resolve()), "--no-compile", "--target", str(site),
        "-r", str(ROOT / "tools" / "requirements-windows-analysis.txt"), "--disable-pip-version-check"], check=True)
    files = ["analyze.py", "local_web.py", "local_operations.py", "Start-VRCA.cmd", "CMakeLists.txt", "requirements.txt",
             "README.md", "LICENSE", "LICENSING.md", "THIRD_PARTY_NOTICES.md", "RELEASE_CHECKLIST.md"]
    for name in files:
        shutil.copy2(ROOT / name, args.output / name)
    for name in ["native", "python", "web", "licenses", "tests", "tools"]:
        shutil.copytree(ROOT / name, args.output / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "AssetRipper", "sdk"))
    (args.output / "bin").mkdir()
    shutil.copy2(args.worker, args.output / "bin" / "VrcAnalysisWorker.exe")
    shutil.copy2(args.launcher, args.output / "VRCA-Local.exe")
    shutil.copy2(args.codec, args.output / "bin" / "vrca_lzma1ext.dll")
    shutil.copy2(args.lzma_runtime, args.output / "bin" / "liblzma-5.dll")
    exporter = args.output / "tools/AssetRipper"
    exporter.mkdir()
    with zipfile.ZipFile(args.exporter_zip) as archive:
        # Official fixed hash plus a narrow entry allowlist; no logs/configs.
        for name in ("AssetRipper.GUI.Free.exe", "capstone.dll"):
            (exporter / name).write_bytes(archive.read(name))
    for name in ("com.vrchat.base", "com.vrchat.avatars"):
        shutil.copytree(args.sdk_root / name, args.output / "tools/sdk" / name)
    packages = []
    for distribution in sorted(importlib.metadata.distributions(path=[str(site)]), key=lambda d: d.metadata["Name"].lower()):
        notices = []
        for entry in distribution.files or []:
            if "license" in str(entry).lower() or "copying" in str(entry).lower() or "notice" in str(entry).lower():
                resolved = distribution.locate_file(entry).resolve()
                if resolved.is_file() and resolved.is_relative_to(args.output.resolve()):
                    notices.append(str(resolved.relative_to(args.output.resolve())).replace("\\", "/"))
        if not notices:
            raise ValueError(f"Missing licence files: {distribution.metadata['Name']}")
        packages.append(dict(name=distribution.metadata["Name"], version=distribution.version,
            license=distribution.metadata.get("License-Expression") or distribution.metadata.get("License"),
            notices=notices))
    manifest = dict(schema=1, python_zip_sha256=args.python_sha256.lower(),
        exporter_zip_sha256=digest(args.exporter_zip), lzma_sha256=digest(args.lzma_runtime),
        third_party_components=[dict(name="AssetRipper", version="2.0.0", license="GPL-3.0",
            source="https://github.com/AssetRipper/AssetRipper/tree/2.0.0"),
            dict(name="VRChat SDK", version="3.10.4", license="VRChat SDK terms; not AGPL",
                 terms="https://hello.vrchat.com/legal/sdk")],
        worker_sha256=digest(args.worker), launcher_sha256=digest(args.launcher), packages=packages,
        omitted_dependencies=["fmod_toolkit", "pyfmodex"],
        wheels=[dict(name=p.name, sha256=digest(p)) for p in sorted(args.wheelhouse.glob("*.whl"))
                if not p.name.lower().startswith(("fmod_toolkit-", "pyfmodex-"))],
        files=[dict(path=p.relative_to(args.output).as_posix(), sha256=digest(p), bytes=p.stat().st_size)
               for p in sorted(args.output.rglob("*")) if p.is_file()])
    (args.output / "BUNDLE-MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(dict(bundle=str(args.output), packages=len(packages), files=len(manifest["files"]))))


if __name__ == "__main__":
    main()

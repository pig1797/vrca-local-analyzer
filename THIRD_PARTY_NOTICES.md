# Third-party notices

## UnityPy

- Upstream: https://github.com/K0lb3/UnityPy
- Tested dependency: UnityPy 1.25.0 (installed through pip, not vendored here).
- License: MIT.
- Copyright (c) 2019-2021 K0lb3.

The MIT notice from the tested distribution is retained in `licenses/UnityPy-MIT.txt`.

UnityPy installs additional dependencies with their own licenses. The source repository does not vendor those installed packages or their native libraries. The separate Windows portable bundle retains all included distributions' notices in `runtime/Lib/site-packages`, CPython's bundled component notices in `runtime/LICENSE.txt`, and an exact version/hash/notice inventory in `BUNDLE-MANIFEST.json`.

The analysis-only portable build uses `tools/requirements-windows-analysis.txt` with `--no-deps`. It deliberately excludes `fmod_toolkit`, its bundled FMOD DLL, and `pyfmodex`: audio export and UnityPy's multimedia export APIs are not features of this bundle. No substitute audio stub is installed. The upstream UnityPy metadata still lists these dependencies, so a generic `pip check` of this deliberately reduced runtime is not an acceptance test for the supported analysis path.

Included packages use their original MIT/BSD/Apache/Pillow licensing and bundled notices, not this project's AGPL license. Native extensions may contain multiple upstream notices; preserve each installed license file, not just package metadata. The MSVC portable worker uses the static CRT; no additional separately copied MSVC redistributable DLL is supplied by this project. CPython's own runtime DLLs and licenses are retained unchanged.

## XZ Utils / liblzma

The strict writer codec includes official XZ 5.8.3 public API headers under
`native/third_party/xz/include`, from `tukaani-project/xz` tag `v5.8.3`.
Copyright (C) The XZ Utils authors and contributors. Headers and liblzma are
under 0BSD; see `licenses/XZ-0BSD.txt` and `licenses/XZ-COPYING.txt`.
The Windows bundle contains liblzma from the locally verified Git for Windows
distribution; its exact binary SHA is recorded in the bundle manifest.
Source: https://github.com/tukaani-project/xz/tree/v5.8.3

## AssetRipper

The optional/portable project exporter invokes the unchanged official
AssetRipper 2.0.0 process. This is a separate GPL-3.0 component, not relicensed
as project-owned source. Its licence is retained in
`licenses/AssetRipper-GPL3.txt`; corresponding source and dependency/build
instructions: https://github.com/AssetRipper/AssetRipper/tree/2.0.0 .
Windows official release archive SHA is pinned in `tools/package_windows.py`.
Keep the upstream licence and source reference when redistributing the binary.
Bundled capstone is part of that official archive; the Capstone BSD notice is
retained in `licenses/Capstone-BSD.txt` (upstream 5.0.6 notice).
Upstream source: https://github.com/capstone-engine/capstone .

## VRChat SDK

The source repository does not vendor the SDK. An explicitly supplied local
SDK 3.10.4 may accompany a locally built portable bundle and recovered project;
keep its package `license.txt` files and follow https://hello.vrchat.com/legal/sdk .
It is not AGPL and the project licence does not grant SDK redistribution rights.
Review those terms separately before publicly redistributing a bundle containing it.

## Toolchains and platforms

Python, CMake and C++ compiler toolchains are build/runtime prerequisites, not included source or bundled installers. No Unity, VRChat or VMProtect SDK is included. Product/platform names identify interoperable file formats and are not an endorsement.

This notice is not a claim that a complete legal/provenance audit of all historical project code has been performed. Owner confirmation of source rights and the final project license remain release gates.

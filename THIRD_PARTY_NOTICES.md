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

## Toolchains and platforms

Python, CMake and C++ compiler toolchains are build/runtime prerequisites, not included source or bundled installers. No Unity, VRChat or VMProtect SDK is included. Product/platform names identify interoperable file formats and are not an endorsement.

This notice is not a claim that a complete legal/provenance audit of all historical project code has been performed. Owner confirmation of source rights and the final project license remain release gates.

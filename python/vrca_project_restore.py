"""Recover an exported project without executing model code or mutating its source.

Only data from an already-completed AssetRipper export enters this module.
The trusted SDK profile and editor helper are release files, never upload options.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict, deque
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import time
import zipfile

HERE = Path(__file__).resolve().parent
GUID = re.compile(r"\bguid:\s*([0-9a-fA-F]{32})\b")
META_GUID = re.compile(r"^guid:\s*([0-9a-fA-F]{32})\s*$", re.M)
SCRIPT_REF = re.compile(r"(\b(?:m_Script|script):\s*)\{fileID:\s*(-?\d+),\s*guid:\s*([0-9a-fA-F]{32}),\s*type:\s*3\}")
PPTR = re.compile(r"\{fileID:\s*(-?\d+),\s*guid:\s*([0-9a-fA-F]{32}),\s*type:\s*([0-9]+)\}")
SAFE_EXT = {'.asset', '.prefab', '.unity', '.mat', '.controller', '.overridecontroller',
    '.anim', '.mask', '.shader', '.cginc', '.hlsl', '.fbx', '.obj', '.png', '.jpg',
    '.jpeg', '.tga', '.dds', '.exr', '.hdr', '.psd', '.bmp', '.tif', '.tiff', '.wav',
    '.ogg', '.mp3', '.mp4', '.webm', '.ttf', '.otf', '.rendertexture', '.cubemap',
    '.physicmaterial', '.physicsmaterial2d', '.lighting', '.flare', '.txt', '.json', '.bytes'}
TEXT_EXT = {'.asset', '.prefab', '.unity', '.mat', '.controller', '.overridecontroller',
    '.anim', '.mask', '.rendertexture', '.cubemap', '.physicmaterial', '.physicsmaterial2d',
    '.lighting', '.flare'}
MAX_FILES = 80000
MAX_BYTES = 8 * 1024**3
MAX_TEXT = 160 * 1024**2
BUILTIN_GUIDS = {'0000000000000000e000000000000000', '0000000000000000f000000000000000', '0' * 32}
UNITY_MODULES = ('ai androidjni animation assetbundle audio cloth director imageconversion imgui '
    'jsonserialize particlesystem physics physics2d screencapture terrain terrainphysics tilemap '
    'ui uielements umbra unityanalytics unitywebrequest unitywebrequestassetbundle '
    'unitywebrequestaudio unitywebrequesttexture unitywebrequestwww vehicles video vr wind xr').split()


def sha256(file):
    h = hashlib.sha256()
    with Path(file).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def atomic_json(file, value):
    file = Path(file)
    temp = file.with_name(file.name + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temp.replace(file)


def inventory(root):
    """Bounded, link-free input; reject unsafe archive paths before copying."""
    root = Path(root)
    count, total, entries = 0, 0, 0
    result = []
    for p in root.rglob('*'):
        entries += 1
        if entries > MAX_FILES * 2:
            raise ValueError('project_size_limit')
        if p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()):
            raise ValueError('project_link_forbidden')
        rel = p.relative_to(root).as_posix()
        if any(c in rel for c in ('\\', '\n', '\r', '\x00', ':')) or any(x in {'.', '..'} for x in p.relative_to(root).parts):
            raise ValueError('project_path_unsafe')
        if p.is_file():
            count += 1
            total += p.stat().st_size
            if count > MAX_FILES or total > MAX_BYTES:
                raise ValueError('project_size_limit')
            result.append(p)
    return sorted(result)


def read_text(p, maximum=MAX_TEXT):
    if p.stat().st_size > maximum:
        raise ValueError('project_text_limit')
    return p.read_text(encoding='utf-8-sig')


def index_metas(root):
    by_guid = {}
    for p in inventory(root):
        if p.suffix != '.meta':
            continue
        match = META_GUID.search(read_text(p, 1024 * 1024))
        if not match:
            raise ValueError('project_meta_guid_missing')
        guid = match.group(1).lower()
        if guid in by_guid:
            raise ValueError('project_duplicate_guid')
        if not p.with_suffix('').exists():
            raise ValueError('project_orphan_meta')
        by_guid[guid] = p.with_suffix('')
    return by_guid


def copy_file(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def write_meta(p, guid, folder=False):
    suffix = 'folderAsset: yes\nDefaultImporter:\n  externalObjects: {}\n' if folder else 'DefaultImporter:\n  externalObjects: {}\n'
    p.with_name(p.name + '.meta').write_text('fileFormatVersion: 2\nguid: ' + guid + '\n' + suffix, encoding='utf-8')


def model_guid(source_hash, original):
    return hashlib.sha256(('vpf-project-r1:' + source_hash + ':' + original).encode()).hexdigest()[:32]


def stable_guid(name):
    return hashlib.sha256(('vpf-recovery-tools-r1:' + name).encode()).hexdigest()[:32]


def sdk_index(sdk_root, profile):
    versions = {}
    all_guids = {}
    shaders = {}
    for name in ('com.vrchat.base', 'com.vrchat.avatars'):
        root = Path(sdk_root) / name
        package = json.loads(read_text(root / 'package.json', 1024 * 1024))
        if package.get('name') != name or package.get('version') != profile['sdk_version']:
            raise ValueError('sdk_profile_version_mismatch')
        versions[name] = package['version']
        for guid, file in index_metas(root).items():
            if guid in all_guids:
                raise ValueError('sdk_duplicate_guid')
            all_guids[guid] = file
            if file.suffix == '.shader' and file.exists():
                match = re.search(r'^\s*Shader\s+"([^"\n]+)"', read_text(file), re.M)
                if match:
                    shaders[match.group(1)] = guid
    for value in profile['script_remap'].values():
        guid = GUID.search(value).group(1)
        if guid not in all_guids:
            raise ValueError('sdk_profile_guid_missing')
    return versions, all_guids, shaders


def build_unitypackage(project, destination, selected=None):
    assets = project / 'Assets'
    indexed = index_metas(assets)
    allowed = set(indexed)
    if selected is not None:
        # Dependencies and parent folder metas are always included. SDK stays external.
        allowed = set()
        queue = deque(selected)
        paths = {p: g for g, p in indexed.items()}
        while queue:
            guid = queue.popleft()
            if guid in allowed or guid not in indexed:
                continue
            allowed.add(guid)
            p = indexed[guid]
            for parent in p.parents:
                if parent == assets:
                    break
                if parent in paths:
                    queue.append(paths[parent])
            if p.is_file() and p.suffix in TEXT_EXT:
                queue.extend(m.group(1).lower() for m in GUID.finditer(read_text(p)))
    with destination.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=3) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                for guid in sorted(allowed):
                    p = indexed[guid]
                    directory = tarfile.TarInfo(guid + '/')
                    directory.type = tarfile.DIRTYPE; directory.mode = 0o755; directory.mtime = 0
                    tar.addfile(directory)
                    entries = [('asset.meta', p.with_name(p.name + '.meta').read_bytes()),
                        ('pathname', p.relative_to(project).as_posix().encode('utf-8'))]
                    for name, data in entries:
                        info = tarfile.TarInfo(guid + '/' + name)
                        info.size = len(data); info.mode = 0o644; info.mtime = 0
                        tar.addfile(info, io.BytesIO(data))
                    if p.is_file():
                        info = tarfile.TarInfo(guid + '/asset')
                        info.size = p.stat().st_size; info.mode = 0o644; info.mtime = 0
                        with p.open('rb') as content:
                            tar.addfile(info, content)
    return len(allowed)


def restore(raw, output, source, sdk_root, progress=None):
    began = time.monotonic()
    raw, output, source, sdk_root = map(lambda p: Path(p).resolve(), (raw, output, source, sdk_root))
    if not (raw / 'Assets').is_dir() or not source.is_file():
        raise ValueError('project_input_missing')
    for p in (raw, source, sdk_root):
        if output == p or output in p.parents or p in output.parents:
            raise ValueError('project_output_overlap')
    if output.exists():
        raise ValueError('project_output_exists')
    profile = json.loads(read_text(HERE / 'sdk-profile.json'))
    versions, external_guids, official_shaders = sdk_index(sdk_root, profile)
    source_hash = sha256(source)
    files = inventory(raw / 'Assets')
    raw_index = index_metas(raw / 'Assets')
    for guid, script in raw_index.items():
        if guid not in profile['script_remap']: continue
        if script.suffix != '.cs': raise ValueError('sdk_stub_identity_mismatch')
        code = read_text(script, 1024 * 1024)
        ns = re.search(r'^\s*namespace\s+([A-Za-z0-9_.]+)', code, re.M)
        cl = re.search(r'\bclass\s+([A-Za-z0-9_]+)', code)
        if not ns or not cl or ns.group(1) + '.' + cl.group(1) != profile['script_types'][guid]:
            raise ValueError('sdk_stub_identity_mismatch')
    # Namespace all generated GUIDs by source, so different model packages can coexist.
    mapping = {guid: model_guid(source_hash, guid) for guid in raw_index}
    folder = 'Assets/VPFRecovered/' + source_hash[:20]
    project = output / 'UnityProject'
    model_root = project / folder
    model_root.mkdir(parents=True)
    quarantine = project / 'RecoveryData' / 'QuarantinedAssets'
    # GUID repair records are required even when no assets need quarantine.
    quarantine.parent.mkdir(parents=True, exist_ok=True)
    actions = []
    quarantined = []
    approximations = []
    generated = {}
    for original, p in raw_index.items():
        if p.suffix == '.shader' and p.is_file():
            text = read_text(p)
            match = re.search(r'^\s*Shader\s+"([^"\n]+)"', text, re.M)
            if 'DummyShaderTextExporter' in text:
                if match and match.group(1) in official_shaders:
                    generated[original] = official_shaders[match.group(1)]
                    mapping[original] = generated[original]
                    actions.append({'kind': 'official_shader_reference', 'path': p.relative_to(raw).as_posix(), 'shader': match.group(1)})
                else:
                    approximations.append({'path': (Path(folder) / p.relative_to(raw / 'Assets')).as_posix(),
                        'shader': match.group(1) if match else None, 'reason': 'compiled_shader_source_unavailable'})
    by_path = {p: guid for guid, p in raw_index.items()}
    if progress: progress('restoring', {'files': len(files)})
    for file in files:
        rel = file.relative_to(raw / 'Assets')
        asset = file.with_suffix('') if file.suffix == '.meta' else file
        original = by_path.get(asset)
        asset_rel = asset.relative_to(raw / 'Assets')
        unsafe = 'Scripts' in asset_rel.parts or (asset.is_file() and asset.suffix.lower() not in SAFE_EXT)
        replaced_shader = original in generated
        destination = quarantine / rel if unsafe or replaced_shader else model_root / rel
        copy_file(file, destination)
        if file.suffix == '.meta' and asset.is_dir():
            destination.with_suffix('').mkdir(exist_ok=True)
        if file.suffix != '.meta' and (unsafe or replaced_shader):
            quarantined.append({'path': rel.as_posix(), 'reason': 'official_shader_replacement' if replaced_shader else 'untrusted_or_generated_code'})
        if unsafe or replaced_shader:
            continue
        if file.suffix == '.meta' or file.suffix in TEXT_EXT:
            text = read_text(file, 1024 * 1024 if file.suffix == '.meta' else MAX_TEXT)
            # SDK substitution is limited to script-reference keys, not arbitrary GUID fields.
            def replace_script(match):
                original_guid = match.group(3).lower()
                replacement = profile['script_remap'].get(original_guid)
                if not replacement: return match.group(0)
                actions.append({'kind': 'sdk_script_reference', 'path': (Path(folder) / rel).as_posix(),
                    'from_guid': original_guid, 'to_reference': replacement, 'expectedType': profile['script_types'][original_guid]})
                return match.group(1) + replacement
            text = SCRIPT_REF.sub(replace_script, text)
            # Official script substitutions must not pass through the local GUID map.
            text = GUID.sub(lambda m: m.group(0).replace(m.group(1), mapping.get(m.group(1).lower(), m.group(1))), text)
            destination.write_text(text, encoding='utf-8', newline='')
    for p in (project / 'Assets/VPFRecovered', model_root):
        write_meta(p, model_guid(source_hash, p.relative_to(project).as_posix()), True)
    # Generated includes/folders sometimes have no meta. Give them stable names too.
    for p in sorted(model_root.rglob('*')):
        if p.suffix != '.meta' and not p.with_name(p.name + '.meta').exists():
            write_meta(p, model_guid(source_hash, 'generated-meta:' + p.relative_to(model_root).as_posix()), p.is_dir())
    # Use only pinned, trusted SDK packages; never import generated SDK stubs or DLLs.
    for name in versions:
        inventory(sdk_root / name)
        shutil.copytree(sdk_root / name, project / 'Packages' / name)
    (project / 'Packages/manifest.json').write_text(json.dumps({'dependencies': {
        'com.vrchat.base': 'file:com.vrchat.base', 'com.vrchat.avatars': 'file:com.vrchat.avatars',
        'com.unity.test-framework': '1.1.33', 'com.unity.textmeshpro': '3.0.6',
        **{'com.unity.modules.' + module: '1.0.0' for module in UNITY_MODULES}}}, indent=2), encoding='utf-8')
    atomic_json(project / 'Packages/vpm-manifest.json', {'dependencies': {name: {'version': version} for name, version in versions.items()}})
    version_file = raw / 'ProjectSettings/ProjectVersion.txt'
    version_match = re.search(r'^m_EditorVersion:\s*(\S+)', read_text(version_file), re.M) if version_file.exists() else None
    source_version = version_match.group(1) if version_match else None
    (project / 'ProjectSettings').mkdir()
    # Do not import unknown ProjectSettings, startup scenes or arbitrary editor hooks.
    (project / 'ProjectSettings/ProjectVersion.txt').write_text(
        'm_EditorVersion: ' + profile['unity_version'] + '\nm_EditorVersionWithRevision: ' + profile['unity_version'] + ' (' + profile['unity_revision'] + ')\n', encoding='utf-8')
    tools = project / 'Assets/VPFRecoveryTools/Editor'
    tools.mkdir(parents=True)
    helper = tools / 'VPFRecoveryAssistant.cs'
    copy_file(HERE / helper.name, helper)
    helper.with_name(helper.name + '.meta').write_text('fileFormatVersion: 2\nguid: ' + stable_guid(helper.name) + '\nMonoImporter:\n  serializedVersion: 2\n  defaultReferences: []\n  executionOrder: 0\n', encoding='utf-8')
    asm = tools / 'VPF.Recovery.Editor.asmdef'
    asm.write_text(json.dumps({'name': 'VPF.Recovery.Editor', 'includePlatforms': ['Editor'], 'autoReferenced': True}), encoding='utf-8')
    write_meta(asm, stable_guid(asm.name))
    for p in (tools.parent, tools):
        write_meta(p, stable_guid(p.relative_to(project).as_posix()), True)
    if progress: progress('checking_references', {})
    restored_index = index_metas(project / 'Assets')
    findings = []
    missing_counts = Counter()
    script_missing = 0
    reference_count = 0
    for p in inventory(model_root):
        if p.suffix not in TEXT_EXT: continue
        text = read_text(p)
        scripts = {(m.group(2), m.group(3).lower()) for m in SCRIPT_REF.finditer(text)}
        for match in PPTR.finditer(text):
            fileid, guid, ref_type = match.groups()
            guid = guid.lower()
            if fileid == '0': continue
            reference_count += 1
            if guid in restored_index or guid in external_guids or guid in BUILTIN_GUIDS: continue
            is_script = (fileid, guid) in scripts
            script_missing += int(is_script)
            missing_counts[guid] += 1
            if len(findings) < 4000:
                findings.append({'kind': 'missing_script' if is_script else 'missing_external_reference',
                    'path': p.relative_to(project).as_posix(), 'guid': guid, 'fileId': fileid})
    prefabs = sorted(p.relative_to(project).as_posix() for p in model_root.rglob('*.prefab'))
    roots = [p for p in prefabs if Path(p).parent == Path(folder)]
    if not prefabs:
        raise ValueError('project_prefab_missing')
    warnings = []
    if source_version != profile['unity_version']: warnings.append('unity_source_version_differs_or_unknown')
    if missing_counts: warnings.append('missing_dependencies')
    if approximations: warnings.append('approximate_shaders')
    # Compiled data alone cannot establish original-code or runtime fidelity.
    report = {'schema': 1, 'sourceSha256': source_hash, 'modelRoot': folder,
        'unityVersion': profile['unity_version'], 'sourceUnityVersion': source_version,
        'sdkVersions': versions, 'status': 'partial_recovery' if script_missing else 'needs_dependencies' if warnings else 'recovered_data',
        'unityImportVerified': False, 'runtimeVerified': False, 'passwordLockChanged': False,
        'mainPrefab': (roots or prefabs)[0], 'prefabs': prefabs,
        'counts': {'assets': len(restored_index), 'referencesChecked': reference_count,
            'missingReferences': sum(missing_counts.values()), 'missingScriptReferences': script_missing,
            'missingGuids': len(missing_counts), 'quarantinedFiles': len(quarantined),
            'approximateShaders': len(approximations), 'sdkRemaps': sum(x['kind'] == 'sdk_script_reference' for x in actions)},
        'warnings': warnings, 'findings': findings, 'findingsTruncated': sum(missing_counts.values()) > len(findings),
        'shaderApproximations': approximations, 'quarantined': quarantined,
        'repairs': actions, 'limits': {'originalSourceProject': False, 'originalScripts': False,
            'shaderSourceRecovered': False, 'reuploadGuaranteed': False}}
    report_file = model_root / 'VPFRecoveryReport.json'
    atomic_json(report_file, report)
    write_meta(report_file, model_guid(source_hash, 'VPFRecoveryReport.json'))
    atomic_json(project / 'RecoveryData/guid-map.json', mapping)
    readme = ('用 Unity ' + profile['unity_version'] + ' 打开本目录（不是 Assets 子目录）。\n'
        '等待首次依赖下载与导入，打开菜单 VPF → 工程恢复助手，选择本模型的报告。\n'
        '助手可定位主 Prefab、创建独立预览场景并检查缺失组件/材质。\n'
        '导入已有工程：先安装 VRChat Avatars SDK ' + profile['sdk_version'] + '，再导入 unitypackage。\n'
        '模型位于独立来源目录，不覆盖其它模型；资源包不捆绑重复 SDK。\n'
        'RecoveryData 保留被隔离的生成脚本及 GUID 修复记录，不要直接放回 Assets。\n'
        '此为构建包中的数据恢复，不是原作者源工程，也不表示密码已移除。\n'
        '编译后的自定义 Shader/C# 源不能完整恢复；缺依赖以助手报告为准。\n'
        '不保证模型可原样重新上传。\n')
    (project / '开始使用.txt').write_text(readme, encoding='utf-8')
    if sha256(source) != source_hash:
        raise ValueError('project_source_changed')
    if progress: progress('packaging', {})
    # Report remains unverified until an actual Unity import has been measured.
    output.mkdir(exist_ok=True)
    package = output / 'model-assets.unitypackage'
    package_count = build_unitypackage(project, package)
    archive = output / 'unity-project.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=3, allowZip64=True) as zip_out:
        for p in inventory(project):
            zip_out.write(p, 'UnityProject/' + p.relative_to(project).as_posix())
    # Validate both containers, not just that they exist or stopped growing.
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None: raise ValueError('project_zip_corrupt')
    with tarfile.open(package, 'r:gz') as t:
        package_files = t.getnames()
        if len([n for n in package_files if n.endswith('/pathname')]) != package_count:
            raise ValueError('project_unitypackage_corrupt')
    artifacts = [{'kind': kind, 'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha256(p)}
        for kind, p in (('project', archive), ('assets', package))]
    receipt = {'schema': 1, 'ok': True, 'sourceSha256': source_hash, 'sourceUnchanged': True,
        'status': report['status'], 'counts': report['counts'], 'unityImportVerified': False,
        'artifacts': artifacts, 'seconds': round(time.monotonic() - began, 3)}
    atomic_json(output / 'receipt.json', receipt)
    return receipt


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--raw', required=True); ap.add_argument('--output', required=True)
    ap.add_argument('--source', required=True); ap.add_argument('--sdk-root', required=True)
    args = ap.parse_args()
    print(json.dumps(restore(args.raw, args.output, args.source, args.sdk_root,
        lambda stage, detail: print(json.dumps({'stage': stage, **detail}), flush=True))), flush=True)

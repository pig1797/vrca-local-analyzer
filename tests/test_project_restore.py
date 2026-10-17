"""Full synthetic recovery with zero quarantined files reproduces the live failure."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

BASE = Path(__file__).resolve().parents[1] / 'python'
spec = importlib.util.spec_from_file_location('restore', BASE / 'vrca_project_restore.py')
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class RestoreRegression(unittest.TestCase):
    def fixture(self, root, quarantine):
        raw = root / 'raw'; assets = raw / 'Assets'; assets.mkdir(parents=True)
        prefab = assets / 'Avatar.prefab'
        prefab.write_text('%YAML 1.1\n--- !u!1 &100\nGameObject:\n  m_Name: SyntheticAvatar\n', encoding='utf-8')
        restore.write_meta(prefab, 'a' * 32)
        if quarantine:
            script = assets / 'Scripts/Generated.cs'; script.parent.mkdir()
            script.write_text('class Generated {}', encoding='utf-8')
            restore.write_meta(script, 'b' * 32)
        source = root / 'source.vrca'; source.write_bytes(b'UnityFS\0synthetic-only')
        trusted = root / 'trusted'; trusted.mkdir()
        (trusted / 'sdk-profile.json').write_text(json.dumps({'script_remap': {}, 'script_types': {},
            'unity_version': '2022.3.22f1', 'unity_revision': 'test', 'sdk_version': '3.10.4'}))
        (trusted / 'VPFRecoveryAssistant.cs').write_text('// trusted test helper\n')
        for name in ('com.vrchat.base', 'com.vrchat.avatars'):
            package = root / 'sdk' / name; package.mkdir(parents=True)
            (package / 'package.json').write_text(json.dumps({'name': name, 'version': '3.10.4'}))
        return raw, source, trusted

    def run_recovery(self, quarantine):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); raw, source, trusted = self.fixture(root, quarantine)
            before = restore.sha256(source); output = root / 'output'
            with patch.object(restore, 'HERE', trusted):
                result = restore.restore(raw, output, source, root / 'sdk')
            self.assertTrue(result['ok'])
            self.assertTrue(result['sourceUnchanged'])
            self.assertEqual(restore.sha256(source), before)
            self.assertEqual(result['counts']['quarantinedFiles'], int(quarantine))
            self.assertEqual(result['counts']['missingReferences'], 0)
            guid_map = output / 'UnityProject/RecoveryData/guid-map.json'
            self.assertTrue(guid_map.is_file())
            with zipfile.ZipFile(output / 'unity-project.zip') as archive:
                self.assertIsNone(archive.testzip())
                self.assertIn('UnityProject/RecoveryData/guid-map.json', archive.namelist())
                self.assertFalse(any(name.endswith('.cs') and '/Assets/' in name and 'Generated' in name for name in archive.namelist()))
            with tarfile.open(output / 'model-assets.unitypackage') as archive:
                paths = [archive.extractfile(item).read().decode() for item in archive.getmembers() if item.name.endswith('/pathname')]
                self.assertTrue(any(path.endswith('/Avatar.prefab') for path in paths))
                self.assertFalse(any('Generated.cs' in path for path in paths))

    def test_no_quarantined_files_still_writes_guid_map(self): self.run_recovery(False)
    def test_quarantined_generated_code_stays_outside_assets(self): self.run_recovery(True)

    def test_duplicate_guids_remain_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('a', 'b'):
                file = root / name; file.touch(); restore.write_meta(file, 'c' * 32)
            with self.assertRaisesRegex(ValueError, 'project_duplicate_guid'): restore.index_metas(root)


if __name__ == '__main__': unittest.main(verbosity=2)

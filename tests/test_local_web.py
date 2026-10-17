"""Loopback HTTP/cleanup tests. Only synthetic files; no customer data."""
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import local_web as web


class Finished:
    returncode = 0
    def poll(self):
        return 0


class WebTests(unittest.TestCase):
    def setUp(self):
        self.started = []
        def runner(folder):
            self.started.append(folder)
            (folder / "progress").write_text("verifying")
            (folder / "result.json").write_text(json.dumps(dict(report=dict(results=[], local_execution=dict(runtime_tested=False)), menu=None)))
            return Finished()
        self.app = web.LocalApp(Path("not-executed"), runner=runner)
        self.server = web.LocalServer(self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.app.close()

    def request(self, method, path, body=None, headers=None, local=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        self.addCleanup(connection.close)
        values = {"X-VRCA-Local": "1"} if local else {}
        values.update(headers or {})
        connection.request(method, path, body=body, headers=values)
        response = connection.getresponse()
        payload = response.read()
        return response.status, payload, dict(response.getheaders())

    def upload(self, payload=b"UnityFS\x00SYNTHETIC", **headers):
        return self.request("POST", "/api/analyses", payload, {"X-File-Name": "%E6%A8%A1%E5%9E%8B.vrca", **headers})

    def test_assets_and_security_headers(self):
        for asset in web.ASSETS:
            status, data, headers = self.request("GET", asset, local=False)
            self.assertEqual(status, 200)
            self.assertTrue(data)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_cross_origin_host_and_missing_capability(self):
        for headers in [{"Origin": "https://evil.example"}, {"Origin": "null"},
                        {"Host": "evil.example"}, {"Sec-Fetch-Site": "cross-site"}]:
            self.assertEqual(self.request("GET", "/api/health", headers=headers)[0], 403)
            self.assertEqual(self.upload(**headers)[0], 403)
        self.assertEqual(self.request("GET", "/api/health", local=False)[0], 403)
        self.assertEqual(self.request("POST", "/api/shutdown", local=False)[0], 403)

    def test_no_arbitrary_file_routes(self):
        for route in ["/../analyze.py", "/%2e%2e/analyze.py", "/local_web.py", "/.env", "/api/file?path=anything"]:
            self.assertEqual(self.request("GET", route)[0], 404)

    def test_upload_result_delete_and_input_cleanup(self):
        status, data, _ = self.upload()
        self.assertEqual(status, 202)
        identity = json.loads(data)["id"]
        self.assertEqual(self.request("GET", f"/api/analyses/{identity}")[0], 200)
        status, data, _ = self.request("GET", f"/api/analyses/{identity}/result")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(data)["report"]["local_execution"]["runtime_tested"])
        self.assertTrue((self.started[0] / "input.vrca").exists())
        self.assertEqual(self.request("DELETE", f"/api/analyses/{identity}")[0], 200)
        self.assertFalse(self.started[0].exists())
        self.assertEqual(self.request("GET", f"/api/analyses/{identity}/result")[0], 404)

    def test_limits_extension_and_invalid_signature(self):
        self.assertEqual(self.upload(**{"Content-Length": str(web.MAX_UPLOAD + 1)})[0], 413)
        self.assertEqual(self.upload(**{"X-File-Name": "source.exe"})[0], 400)
        self.assertEqual(self.upload(b"INVALID-SYNTHETIC")[0], 400)
        self.assertEqual(len(self.started), 0)
        self.assertFalse((self.app.job["folder"] / "input.vrca").exists())

    def test_transfer_encoding_rejected(self):
        self.assertEqual(self.upload(**{"Transfer-Encoding": "chunked"})[0], 411)

    def test_operation_body_and_confirmation_are_strict(self):
        _, payload, _ = self.upload()
        identity = json.loads(payload)["id"]
        for kind, body in [("remove", {}), ("remove", {"confirmed": False}),
                           ("remove", {"confirmed": True, "plan": {}}),
                           ("export", {"source": "C:/arbitrary"}), ("export", {"path": "anything"})]:
            self.assertEqual(self.request("POST", f"/api/analyses/{identity}/{kind}", json.dumps(body))[0], 409)
        self.assertEqual(self.request("GET", f"/api/analyses/{identity}/operation")[0], 200)
        self.assertEqual(self.request("GET", f"/api/analyses/{identity}/downloads/model", local=False)[0], 409)

    def test_verified_artifact_download_and_range(self):
        _, payload, _ = self.upload()
        identity = json.loads(payload)["id"]
        folder = self.app.job["folder"]
        (folder / "remove").mkdir()
        (folder / "remove/unlocked.vrca").write_bytes(b"SYNTHETIC-ARTIFACT")
        (folder / "remove.result.json").write_text(json.dumps(dict(ok=True, artifacts=[dict(key="model", bytes=999, sha256="a" * 64)])))
        # Size mismatch does not become a downloadable success.
        route = f"/api/analyses/{identity}/downloads/model"
        self.assertEqual(self.request("GET", route, local=False)[0], 409)
        (folder / "remove.result.json").write_text(json.dumps(dict(ok=True, artifacts=[dict(key="model", bytes=len(b"SYNTHETIC-ARTIFACT"), sha256="a" * 64)])))
        code, body, headers = self.request("GET", route, local=False)
        self.assertEqual((code, body), (200, b"SYNTHETIC-ARTIFACT"))
        self.assertEqual(headers["Accept-Ranges"], "bytes")
        code, body, headers = self.request("GET", route, headers={"Range": "bytes=2-5"}, local=False)
        self.assertEqual((code, body), (206, b"NTHE"))
        self.assertEqual(self.request("GET", route, headers={"Range": "bytes=999-"}, local=False)[0], 416)
        self.assertEqual(self.request("GET", route, headers={"Sec-Fetch-Site": "cross-site"}, local=False)[0], 403)

    def test_operation_blocks_new_upload_and_expiry_while_running(self):
        _, payload, _ = self.upload()
        identity = json.loads(payload)["id"]
        self.app.status(identity)
        class Pending:
            def poll(self): return None
        with patch.object(self.app, "launch", return_value=Pending()):
            self.assertEqual(self.request("POST", f"/api/analyses/{identity}/export", '{"source":"original"}')[0], 202)
        self.app.job["finished"] = time.monotonic() - web.TTL - 1
        self.app.refresh()
        self.assertEqual(self.upload()[0], 409)
        self.assertEqual(self.request("POST", f"/api/analyses/{identity}/remove", '{"confirmed":true}')[0], 409)
        self.app.job["operation"]["process"] = Finished()
        self.app.refresh()
        self.assertEqual(self.app.job["operation"]["state"], "failed")

    def test_concurrent_upload_rejected(self):
        current = self.app.reserve()
        self.assertEqual(self.upload()[0], 409)
        self.assertIs(self.app.job, current)

    def test_expiry_removes_report(self):
        self.upload()
        self.app.refresh()
        folder = self.app.job["folder"]
        self.app.job["finished"] = time.monotonic() - web.TTL - 1
        self.app.refresh()
        self.assertIsNone(self.app.job)
        self.assertFalse(folder.exists())

    def test_child_failure_is_not_success(self):
        def runner(folder):
            (folder / "error.json").write_text('{"error":"synthetic failure"}')
            result = Finished(); result.returncode = 1
            return result
        self.app.runner = runner
        _, data, _ = self.upload()
        identity = json.loads(data)["id"]
        status = json.loads(self.request("GET", f"/api/analyses/{identity}")[1])
        self.assertEqual(status["state"], "failed")
        self.assertEqual(self.request("GET", f"/api/analyses/{identity}/result")[0], 409)

    def test_oversized_report_rejected(self):
        _, data, _ = self.upload()
        identity = json.loads(data)["id"]
        with patch.object(web, "MAX_RESULT", 1):
            self.assertEqual(self.request("GET", f"/api/analyses/{identity}/result")[0], 500)

    def test_child_tree_cancel(self):
        if os.name == "nt":
            options = dict(creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            options = dict(start_new_session=True)
        self.app.runner = lambda folder: subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], **options)
        _, data, _ = self.upload()
        identity = json.loads(data)["id"]
        proc = self.app.job["process"]
        self.assertIsNone(proc.poll())
        self.assertEqual(self.request("DELETE", f"/api/analyses/{identity}")[0], 200)
        self.assertIsNotNone(proc.poll())
        self.assertFalse(any(self.app.root.iterdir()))

    def test_menu_types_roots_and_text_not_html(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "graph.json"
            path.write_text(json.dumps(dict(menus=[dict(id="42", name="<script>synthetic</script>", controls=[dict(type=3, submenu=43), dict(type=1, value=2)]) , dict(id="43", controls=[])], active_root_menu_ids=[42])))
            dto = web.menu_dto(path, "a" * 64)
            self.assertEqual(dto["root"], "42")
            self.assertEqual(dto["menus"][0]["controls"][0]["type"], "SubMenu")
            self.assertEqual(dto["menus"][0]["controls"][1]["type"], "Button")
            self.assertIsNone(dto["menus"][0]["controls"][0]["icon"])

    def test_shutdown_requires_local_header_and_stops_server(self):
        self.assertEqual(self.request("POST", "/api/shutdown", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request("POST", "/api/shutdown")[0], 200)
        self.thread.join(3)
        self.assertFalse(self.thread.is_alive())


if __name__ == "__main__":
    unittest.main()

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from cloud_d.application import CloudDApplication
from cloud_d.server import CloudDHandler


class TestServerRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="cloud_d_test_server_")
        cls.orig_data_dir = os.environ.get("CLOUD_D_DATA_DIR")
        cls.orig_staff_code = os.environ.get("CLOUD_D_STAFF_REGISTRATION_CODE")
        os.environ["CLOUD_D_DATA_DIR"] = cls.temp_dir
        os.environ["CLOUD_D_STAFF_REGISTRATION_CODE"] = "staff-pass-secret-code"

        cls.app = CloudDApplication()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CloudDHandler)
        cls.server.cloud_d_app = cls.app
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.close()

        if cls.orig_data_dir is not None:
            os.environ["CLOUD_D_DATA_DIR"] = cls.orig_data_dir
        else:
            os.environ.pop("CLOUD_D_DATA_DIR", None)

        if cls.orig_staff_code is not None:
            os.environ["CLOUD_D_STAFF_REGISTRATION_CODE"] = cls.orig_staff_code
        else:
            os.environ.pop("CLOUD_D_STAFF_REGISTRATION_CODE", None)

        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _request(self, path, method="GET", body=None, cookie=None):
        url = f"{self.base_url}{path}"
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as response:
                status = response.status
                resp_headers = dict(response.info())
                resp_body = response.read()
                cookie_header = response.headers.get("Set-Cookie")
                try:
                    payload = json.loads(resp_body.decode("utf-8"))
                except Exception:
                    payload = resp_body
                return status, payload, cookie_header
        except urllib.error.HTTPError as err:
            err_body = err.read()
            try:
                payload = json.loads(err_body.decode("utf-8"))
            except Exception:
                payload = err_body
            return err.code, payload, None

    def test_health_endpoint(self):
        status, payload, _ = self._request("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(payload.get("ok"))

    def test_static_assets(self):
        status, html, _ = self._request("/index.html")
        self.assertEqual(status, 200)
        self.assertIn(b"Cloud-D", html)

        status, js, _ = self._request("/cloud-d.js")
        self.assertEqual(status, 200)
        self.assertIn(b"use strict", js)

    def test_auth_and_role_protection(self):
        # 1. Register customer
        status, payload, cookie = self._request(
            "/api/auth/signup",
            method="POST",
            body={
                "email": "cust_srv@example.com",
                "username": "cust_srv",
                "password": "valid_password_123",
                "role": "customer",
            },
        )
        self.assertEqual(status, 201)
        self.assertIsNotNone(cookie)
        cust_cookie = cookie.split(";")[0]

        # 2. Check /api/auth/me with customer cookie
        status, me_payload, _ = self._request("/api/auth/me", cookie=cust_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(me_payload["user"]["username"], "cust_srv")
        self.assertEqual(me_payload["user"]["role"], "customer")

        # 3. Customer tries staff-only simulation control (/api/round) -> 403 Forbidden
        status, err_payload, _ = self._request("/api/round", method="POST", body={}, cookie=cust_cookie)
        self.assertEqual(status, 403)
        self.assertIn("staff accounts", err_payload.get("error", ""))

        # 4. Register staff
        status, payload, staff_cookie_hdr = self._request(
            "/api/auth/signup",
            method="POST",
            body={
                "email": "staff_srv@example.com",
                "username": "staff_srv",
                "password": "valid_password_123",
                "role": "staff",
                "staff_registration_code": "staff-pass-secret-code",
            },
        )
        self.assertEqual(status, 201)
        staff_cookie = staff_cookie_hdr.split(";")[0]

        # 5. Staff calls /api/round -> 200 OK
        status, sim_state, _ = self._request("/api/round", method="POST", body={}, cookie=staff_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(sim_state["round"], 1)

        # 6. Logout customer
        status, logout_res, cleared_cookie = self._request("/api/auth/logout", method="POST", cookie=cust_cookie)
        self.assertEqual(status, 200)
        self.assertTrue(logout_res.get("ok"))

    def test_pwa_and_node_manifest_routes(self):
        # Verify /manifest.json
        status, manifest, _ = self._request("/manifest.json")
        self.assertEqual(status, 200)
        self.assertEqual(manifest.get("short_name"), "Cloud-D")
        self.assertEqual(manifest.get("display"), "standalone")

        # Verify /sw.js
        status, sw, _ = self._request("/sw.js")
        self.assertEqual(status, 200)
        self.assertIn(b"cloud-d-v1", sw)

        # Verify icon routes
        for icon_path in ("/icon-192.png", "/apple-touch-icon.png", "/favicon.ico"):
            status, icon_data, _ = self._request(icon_path)
            self.assertEqual(status, 200)
            self.assertIn(b"<svg", icon_data)

        # Verify /api/nodes requires authentication
        status, err_payload, _ = self._request("/api/nodes")
        self.assertEqual(status, 401)

        # Register a user to test /api/nodes with authentication
        _, _, cookie = self._request(
            "/api/auth/signup",
            method="POST",
            body={
                "email": "nodes_test@example.com",
                "username": "nodes_test",
                "password": "valid_password_123",
                "role": "customer",
            },
        )
        auth_cookie = cookie.split(";")[0]

        status, node_data, _ = self._request("/api/nodes", cookie=auth_cookie)
        self.assertEqual(status, 200)
        self.assertIn("nodes", node_data)
        self.assertEqual(len(node_data["nodes"]), 5)
        self.assertEqual(node_data["implementation"], "single-process")


if __name__ == "__main__":
    unittest.main()

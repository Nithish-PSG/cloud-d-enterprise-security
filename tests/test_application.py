import os
import shutil
import tempfile
import unittest

from cloud_d.application import CloudDApplication
from cloud_d.storage import DuplicateUploadError


class TestCloudDApplication(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cloud_d_test_app_")
        self.orig_data_dir = os.environ.get("CLOUD_D_DATA_DIR")
        self.orig_staff_code = os.environ.get("CLOUD_D_STAFF_REGISTRATION_CODE")
        os.environ["CLOUD_D_DATA_DIR"] = self.temp_dir
        os.environ["CLOUD_D_STAFF_REGISTRATION_CODE"] = "secret-staff-code-12345"

        self.app = CloudDApplication()

    def tearDown(self):
        self.app.close()
        if self.orig_data_dir is not None:
            os.environ["CLOUD_D_DATA_DIR"] = self.orig_data_dir
        else:
            os.environ.pop("CLOUD_D_DATA_DIR", None)

        if self.orig_staff_code is not None:
            os.environ["CLOUD_D_STAFF_REGISTRATION_CODE"] = self.orig_staff_code
        else:
            os.environ.pop("CLOUD_D_STAFF_REGISTRATION_CODE", None)

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_registration_validation(self):
        # Invalid email
        with self.assertRaises(ValueError) as ctx:
            self.app.register_user({
                "email": "invalid-email",
                "username": "alice",
                "password": "valid_password_123",
                "role": "customer",
            })
        self.assertIn("valid email address", str(ctx.exception))

        # Invalid username (too short)
        with self.assertRaises(ValueError) as ctx:
            self.app.register_user({
                "email": "alice@example.com",
                "username": "al",
                "password": "valid_password_123",
                "role": "customer",
            })
        self.assertIn("username with 3–30 letters", str(ctx.exception))

        # Short password
        with self.assertRaises(ValueError) as ctx:
            self.app.register_user({
                "email": "alice@example.com",
                "username": "alice",
                "password": "short",
                "role": "customer",
            })
        self.assertIn("password between 10 and 1024", str(ctx.exception))

    def test_staff_registration_code_enforcement(self):
        # Missing staff code
        with self.assertRaises(ValueError) as ctx:
            self.app.register_user({
                "email": "staff1@example.com",
                "username": "staff1",
                "password": "secure_staff_password_1",
                "role": "staff",
                "staff_registration_code": "",
            })
        self.assertIn("Staff Registration Code is required", str(ctx.exception))

        # Incorrect staff code
        with self.assertRaises(ValueError) as ctx:
            self.app.register_user({
                "email": "staff1@example.com",
                "username": "staff1",
                "password": "secure_staff_password_1",
                "role": "staff",
                "staff_registration_code": "wrong-code",
            })
        self.assertIn("Staff Registration Code is incorrect", str(ctx.exception))

        # Correct staff code
        registered = self.app.register_user({
            "email": "staff1@example.com",
            "username": "staff1",
            "password": "secure_staff_password_1",
            "role": "staff",
            "staff_registration_code": "secret-staff-code-12345",
        })
        self.assertIn("session", registered)
        self.assertEqual(registered["user"]["role"], "staff")

    def test_login_and_session_lifecycle(self):
        self.app.register_user({
            "email": "customer1@example.com",
            "username": "customer1",
            "password": "secure_customer_password_1",
            "role": "customer",
        })

        # Login with correct credentials
        logged_in = self.app.login_user({
            "username": "customer1",
            "password": "secure_customer_password_1",
        })
        token = logged_in["session"]
        self.assertIsNotNone(token)

        # Resolve session
        user = self.app.resolve_session(token)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "customer1")

        # Login with bad password
        with self.assertRaises(ValueError):
            self.app.login_user({
                "username": "customer1",
                "password": "wrong_password_123",
            })

        # Revoke session
        self.app.revoke_session(token)
        self.assertIsNone(self.app.resolve_session(token))

    def test_folder_and_upload_flow(self):
        cust_reg = self.app.register_user({
            "email": "cust@example.com",
            "username": "custuser",
            "password": "secure_password_cust_123",
            "role": "customer",
        })
        cust = cust_reg["user"]

        # Default folder was automatically created
        folders = self.app.list_folders(cust)
        self.assertGreaterEqual(len(folders), 1)
        folder_id = folders[0]["id"]

        # Upload a document
        content = b"Cloud-D test binary content"
        upload_res = self.app.upload_items(
            folder_id=folder_id,
            items=[{"filename": "test.txt", "kind": "document", "content": content}],
            user=cust,
        )
        self.assertEqual(len(upload_res["files"]), 1)

        # Duplicate without duplicate_mode raises DuplicateUploadError
        with self.assertRaises(DuplicateUploadError):
            self.app.upload_items(
                folder_id=folder_id,
                items=[{"filename": "test.txt", "kind": "document", "content": b"new content"}],
                user=cust,
            )

        # Duplicate with new_version succeeds
        res_v2 = self.app.upload_items(
            folder_id=folder_id,
            items=[{"filename": "test.txt", "kind": "document", "content": b"version 2 content"}],
            user=cust,
            duplicate_mode="new_version",
        )
        self.assertEqual(len(res_v2["files"]), 1)

        # Verify downloading file
        files = self.app.storage.list_files(cust)
        current_file = [f for f in files if f["filename"] == "test.txt"][0]
        downloaded = self.app.get_file(current_file["id"], cust)
        self.assertEqual(downloaded["content"], b"version 2 content")

    def test_simulation_round_and_reset(self):
        state1 = self.app.simulate_round()
        self.assertEqual(state1["round"], 1)
        self.assertGreater(len(state1["events"]), 0)

        state2 = self.app.simulate_round()
        self.assertEqual(state2["round"], 2)

        # Reset simulation
        reset_state = self.app.reset()
        self.assertEqual(reset_state["round"], 0)


if __name__ == "__main__":
    unittest.main()

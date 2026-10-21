import os
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path

from cloud_d.storage import (
    DuplicateUploadError,
    EncryptedSQLiteStore,
    StorageIntegrityError,
    StorageKeyError,
)

SAMPLE_NODES = [
    {"id": 0, "name": "Auth Server", "role": "auth"},
    {"id": 1, "name": "API Gateway", "role": "gateway"},
    {"id": 2, "name": "Primary DB", "role": "storage"},
    {"id": 3, "name": "Customer DB", "role": "storage"},
    {"id": 4, "name": "Backup Server", "role": "backup"},
]


class TestEncryptedSQLiteStore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cloud_d_test_store_")
        self.store = EncryptedSQLiteStore(data_dir=self.temp_dir)
        self.store.sync_nodes(SAMPLE_NODES)

    def tearDown(self):
        self.store._connection.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_user(self, email="user@example.com", username="testuser", role="customer"):
        salt = os.urandom(16)
        pwd_hash = os.urandom(32)
        user_id = uuid.uuid4().hex
        return self.store.create_user(
            user_id=user_id,
            email=email,
            username=username,
            display_name=username.capitalize(),
            role=role,
            status="active",
            password_salt=salt,
            password_hash=pwd_hash,
        )

    def test_key_generation_and_persistence(self):
        key_file = Path(self.temp_dir) / "encryption.key"
        self.assertTrue(key_file.exists())
        self.assertEqual(len(key_file.read_bytes()), 32)
        self.assertEqual(self.store.key_source, "generated local key file")

    def test_user_creation_and_credential_lookup(self):
        user = self._make_user(email="alice@example.com", username="alice", role="customer")
        self.assertIsNotNone(user["id"])
        self.assertEqual(user["username"], "alice")
        self.assertEqual(user["role"], "customer")

        fetched = self.store.get_user_by_email("alice@example.com")
        self.assertEqual(fetched["user_id"], user["id"])

        creds = self.store.get_user_credentials("alice")
        self.assertEqual(creds["user_id"], user["id"])

    def test_folder_creation_and_isolation(self):
        cust = self._make_user("c@ex.com", "cust", "customer")
        staff = self._make_user("s@ex.com", "staff", "staff")

        f_cust = self.store.create_folder(cust, "Customer Vault")
        self.assertIn("id", f_cust)
        self.assertEqual(f_cust["name"], "Customer Vault")

        f_staff = self.store.create_folder(staff, "Staff Ops")
        self.assertIn("id", f_staff)
        self.assertEqual(f_staff["name"], "Staff Ops")

        cust_folders = self.store.list_folders(cust)
        staff_folders = self.store.list_folders(staff)

        cust_names = [f["name"] for f in cust_folders]
        staff_names = [f["name"] for f in staff_folders]

        self.assertIn("Customer Vault", cust_names)
        self.assertNotIn("Staff Ops", cust_names)

        self.assertIn("Staff Ops", staff_names)
        self.assertNotIn("Customer Vault", staff_names)

    def test_file_encryption_and_decryption(self):
        cust = self._make_user("c@ex.com", "cust", "customer")
        folder = self.store.create_folder(cust, "Confidential")
        secret_content = b"Super confidential payload 1234567890"

        stored = self.store.save_upload_batch(
            node_id=3,
            folder_id=folder["id"],
            owner_id=cust["id"],
            access_role=cust["role"],
            items=[{"filename": "data.txt", "kind": "document", "content": secret_content}],
            duplicate_mode=None,
        )
        self.assertEqual(len(stored), 1)
        file_id = stored[0]["id"]

        # Check raw database content is encrypted (ciphertext does not contain secret plaintext)
        row = self.store._connection.execute(
            "SELECT ciphertext FROM cloud_files WHERE file_id = ?", (file_id,)
        ).fetchone()
        self.assertNotIn(secret_content, row["ciphertext"])

        # Decrypt through get_file
        read_back = self.store.get_file(file_id, cust)
        self.assertIsNotNone(read_back)
        self.assertEqual(read_back["content"], secret_content)
        self.assertEqual(read_back["filename"], "data.txt")

    def test_duplicate_handling_update_and_replace(self):
        cust = self._make_user("c@ex.com", "cust", "customer")
        folder = self.store.create_folder(cust, "Docs")

        # First save
        stored1 = self.store.save_upload_batch(
            node_id=3,
            folder_id=folder["id"],
            owner_id=cust["id"],
            access_role=cust["role"],
            items=[{"filename": "report.txt", "kind": "document", "content": b"Version 1"}],
        )
        logical_id = stored1[0]["logical_id"]

        # Second save with same filename -> should raise DuplicateUploadError
        with self.assertRaises(DuplicateUploadError):
            self.store.save_upload_batch(
                node_id=3,
                folder_id=folder["id"],
                owner_id=cust["id"],
                access_role=cust["role"],
                items=[{"filename": "report.txt", "kind": "document", "content": b"Version 2"}],
                duplicate_mode=None,
            )

        # Save with duplicate_mode='new_version' -> adds version 2
        stored2 = self.store.save_upload_batch(
            node_id=3,
            folder_id=folder["id"],
            owner_id=cust["id"],
            access_role=cust["role"],
            items=[{"filename": "report.txt", "kind": "document", "content": b"Version 2"}],
            duplicate_mode="new_version",
        )
        self.assertEqual(stored2[0]["version"], 2)

        history = self.store.get_file_versions(logical_id, cust)
        self.assertEqual(len(history), 2)

        # Save with duplicate_mode='replace' -> replaces file and resets to version 1
        stored3 = self.store.save_upload_batch(
            node_id=3,
            folder_id=folder["id"],
            owner_id=cust["id"],
            access_role=cust["role"],
            items=[{"filename": "report.txt", "kind": "document", "content": b"Version 3 Replaced"}],
            duplicate_mode="replace",
        )
        self.assertEqual(stored3[0]["version"], 1)
        history_after = self.store.get_file_versions(stored3[0]["logical_id"], cust)
        self.assertEqual(len(history_after), 1)

    def test_backup_mirroring_and_restore(self):
        cust = self._make_user("c@ex.com", "cust", "customer")
        folder = self.store.create_folder(cust, "Vault")
        content = b"Backup integrity test data"
        stored = self.store.save_upload_batch(
            node_id=3,
            folder_id=folder["id"],
            owner_id=cust["id"],
            access_role=cust["role"],
            items=[{"filename": "test.bin", "kind": "document", "content": content}],
        )
        file_id = stored[0]["id"]

        # Check backup database has the mirror
        backup_row = self.store._connection.execute(
            "SELECT * FROM backup_db.files WHERE file_id = ?", (file_id,)
        ).fetchone()
        self.assertIsNotNone(backup_row)

        # Delete primary file row to simulate deletion/corruption
        with self.store._lock, self.store._connection:
            self.store._connection.execute("DELETE FROM cloud_files WHERE file_id = ?", (file_id,))

        # Verify reading falls back or restore restores it into primary
        restored = self.store.restore_backup_file(file_id, cust)
        self.assertIsNotNone(restored)
        self.assertEqual(restored["id"], file_id)

        # Check that row is back in cloud_files
        primary_row = self.store._connection.execute(
            "SELECT * FROM cloud_files WHERE file_id = ?", (file_id,)
        ).fetchone()
        self.assertIsNotNone(primary_row)

        # Decryption matches original
        decrypted = self.store.get_file(file_id, cust)
        self.assertEqual(decrypted["content"], content)

    def test_startup_rebuild_from_backup_when_primary_lost(self):
        cust = self._make_user("c@ex.com", "cust", "customer")
        folder = self.store.create_folder(cust, "Critical")
        data = b"Critical data to survive primary loss"
        stored = self.store.save_upload_batch(
            node_id=3,
            folder_id=folder["id"],
            owner_id=cust["id"],
            access_role=cust["role"],
            items=[{"filename": "doc.txt", "kind": "document", "content": data}],
        )
        file_id = stored[0]["id"]

        # Close store
        self.store._connection.close()

        # Delete primary sqlite database file
        primary_db_path = Path(self.temp_dir) / "cloud-d.sqlite3"
        primary_db_path.unlink()

        # Re-open store with backup database and key intact
        reopened_store = EncryptedSQLiteStore(data_dir=self.temp_dir)
        try:
            read_back = reopened_store.get_file(file_id, cust)
            self.assertIsNotNone(read_back)
            self.assertEqual(read_back["content"], data)
        finally:
            reopened_store._connection.close()


if __name__ == "__main__":
    unittest.main()

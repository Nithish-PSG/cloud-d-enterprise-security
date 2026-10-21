from __future__ import annotations

import base64
import json
import os
import shutil
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .storage import EncryptedSQLiteStore


def _get_ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    try:
        ctx = ssl.create_default_context()
        return ctx
    except Exception:
        return ssl._create_unverified_context()


REPO_OWNER = os.environ.get("GITHUB_REPO_OWNER", "nithishammu")
REPO_NAME = os.environ.get("GITHUB_REPO_NAME", "cloud-d-enterprise-security")
TARGET_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
STATE_FILE_PATH = "data/cloud_d_state.json"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class GitSyncManager:
    """Manages lightweight JSON state synchronization to Git / GitHub API without binary bloat."""

    def __init__(self, storage: EncryptedSQLiteStore | None = None):
        self.storage = storage
        self.project_root = PROJECT_ROOT
        if storage and hasattr(storage, "data_dir") and storage.data_dir:
            self.data_dir = storage.data_dir
            self.local_state_file = self.data_dir / "cloud_d_state.json"
        else:
            self.data_dir = self.project_root / "data"
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.local_state_file = self.project_root / STATE_FILE_PATH
        self._lock = threading.Lock()

    def get_github_token(self) -> str | None:
        return (
            os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GH_TOKEN")
            or os.environ.get("CLOUD_D_GITHUB_TOKEN")
        )

    def export_state_from_db(self) -> dict[str, Any]:
        """Read users and folders from SQLite and serialize to JSON-safe dictionary."""
        if not self.storage:
            return {}

        users = []
        folders = []
        with self.storage._lock:
            # Export users
            cursor = self.storage._connection.execute(
                "SELECT user_id, email, username, display_name, role, status, password_salt, password_hash, created_at FROM cloud_users"
            )
            for row in cursor.fetchall():
                users.append({
                    "user_id": row["user_id"],
                    "email": row["email"],
                    "username": row["username"],
                    "display_name": row["display_name"],
                    "role": row["role"],
                    "status": row["status"],
                    "password_salt": base64.b64encode(row["password_salt"]).decode("ascii"),
                    "password_hash": base64.b64encode(row["password_hash"]).decode("ascii"),
                    "created_at": row["created_at"],
                })

            # Export folders
            f_cursor = self.storage._connection.execute(
                "SELECT folder_id, scope_key, role, owner_id, node_id, name, created_at FROM cloud_folders"
            )
            for row in f_cursor.fetchall():
                folders.append({
                    "folder_id": row["folder_id"],
                    "scope_key": row["scope_key"],
                    "role": row["role"],
                    "owner_id": row["owner_id"],
                    "node_id": row["node_id"],
                    "name": row["name"],
                    "created_at": row["created_at"],
                })

        return {
            "version": 1,
            "project": "Cloud-D",
            "last_synced": datetime.now(timezone.utc).isoformat(),
            "users": users,
            "folders": folders,
        }

    def import_state_to_db(self, state: dict[str, Any]) -> int:
        """Import users and folders from JSON state dictionary into SQLite."""
        if not self.storage or not state:
            return 0

        imported_count = 0
        users = state.get("users", [])
        folders = state.get("folders", [])

        with self.storage._lock, self.storage._connection:
            for user in users:
                try:
                    salt = base64.b64decode(user["password_salt"])
                    pwd_hash = base64.b64decode(user["password_hash"])
                    self.storage._connection.execute(
                        """
                        INSERT OR IGNORE INTO cloud_users (
                            user_id, email, username, display_name, role, status, password_salt, password_hash, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user["user_id"],
                            user["email"],
                            user.get("username") or user["email"].split("@")[0],
                            user.get("display_name") or user["username"],
                            user["role"],
                            user["status"],
                            salt,
                            pwd_hash,
                            user["created_at"],
                        ),
                    )
                    # Mirror to backup DB as well
                    self.storage._connection.execute(
                        """
                        INSERT OR IGNORE INTO backup_db.users (
                            user_id, email, display_name, role, status, password_salt, password_hash, created_at, username
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user["user_id"],
                            user["email"],
                            user.get("display_name") or user["username"],
                            user["role"],
                            user["status"],
                            salt,
                            pwd_hash,
                            user["created_at"],
                            user.get("username") or user["email"].split("@")[0],
                        ),
                    )
                    imported_count += 1
                except Exception as exc:
                    print(f"Cloud-D sync user import error: {exc}")

            for folder in folders:
                try:
                    self.storage._connection.execute(
                        """
                        INSERT OR IGNORE INTO cloud_folders (
                            folder_id, scope_key, role, owner_id, node_id, name, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            folder["folder_id"],
                            folder["scope_key"],
                            folder["role"],
                            folder.get("owner_id"),
                            folder["node_id"],
                            folder["name"],
                            folder["created_at"],
                        ),
                    )
                except Exception as exc:
                    print(f"Cloud-D sync folder import error: {exc}")

        return imported_count

    def save_local_state(self, state: dict[str, Any] | None = None) -> Path:
        """Write lightweight JSON state file locally."""
        if state is None:
            state = self.export_state_from_db()
        content = json.dumps(state, indent=2, ensure_ascii=False)
        self.local_state_file.write_text(content, encoding="utf-8")
        return self.local_state_file

    def load_local_state(self) -> dict[str, Any] | None:
        """Load lightweight JSON state file locally if present."""
        if self.local_state_file.exists():
            try:
                text = self.local_state_file.read_text(encoding="utf-8")
                return json.loads(text)
            except Exception as exc:
                print(f"Cloud-D error loading local state JSON: {exc}")
        return None

    def pull_from_github(self) -> dict[str, Any] | None:
        """Fetch latest state from GitHub via REST API."""
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{STATE_FILE_PATH}?ref={TARGET_BRANCH}"
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "Cloud-D-App"}
        token = self.get_github_token()
        if token:
            headers["Authorization"] = f"token {token}"

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=_get_ssl_context(), timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "content" in data:
                    raw = base64.b64decode(data["content"]).decode("utf-8")
                    state = json.loads(raw)
                    # Cache locally
                    self.save_local_state(state)
                    return state
        except urllib.error.HTTPError as err:
            if err.code != 404:
                print(f"Cloud-D GitHub pull HTTP error: {err.code}")
        except Exception as exc:
            print(f"Cloud-D GitHub pull error: {exc}")
        return None

    def push_to_github(self, state: dict[str, Any]) -> bool:
        """Push updated state JSON directly to GitHub via REST API."""
        token = self.get_github_token()
        if not token:
            print("Cloud-D Git sync: GITHUB_TOKEN not configured. Data saved locally to data/cloud_d_state.json.")
            return False

        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{STATE_FILE_PATH}"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token}",
            "User-Agent": "Cloud-D-App",
        }

        # Step 1: Check existing SHA for in-place update
        sha = None
        get_req = urllib.request.Request(f"{url}?ref={TARGET_BRANCH}", headers=headers)
        try:
            with urllib.request.urlopen(get_req, context=_get_ssl_context(), timeout=10) as resp:
                existing = json.loads(resp.read().decode("utf-8"))
                sha = existing.get("sha")
        except urllib.error.HTTPError as err:
            if err.code != 404:
                print(f"Cloud-D GitHub check SHA HTTP error: {err.code}")
        except Exception as exc:
            print(f"Cloud-D GitHub check SHA error: {exc}")

        # Step 2: Prepare commit payload
        json_bytes = json.dumps(state, indent=2, ensure_ascii=False).encode("utf-8")
        encoded_content = base64.b64encode(json_bytes).decode("ascii")
        user_count = len(state.get("users", []))
        body: dict[str, Any] = {
            "message": f"sync: update users registry ({user_count} accounts)",
            "content": encoded_content,
            "branch": TARGET_BRANCH,
        }
        if sha:
            body["sha"] = sha

        put_req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", **headers},
            method="PUT",
        )

        try:
            with urllib.request.urlopen(put_req, context=_get_ssl_context(), timeout=15) as resp:
                if resp.status in (200, 201):
                    print(f"Cloud-D Git sync: successfully pushed state to GitHub ({user_count} users).")
                    return True
        except urllib.error.HTTPError as err:
            err_msg = err.read().decode("utf-8", errors="replace")
            print(f"Cloud-D GitHub push HTTP error {err.code}: {err_msg}")
        except Exception as exc:
            print(f"Cloud-D GitHub push error: {exc}")

        return False

    def push_to_local_git(self) -> bool:
        """Fallback to local git CLI if git is installed and in a repository."""
        git_exe = shutil.which("git")
        if not git_exe or not (self.project_root / ".git").exists():
            return False

        try:
            subprocess.run(
                [git_exe, "add", STATE_FILE_PATH],
                cwd=str(self.project_root),
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [git_exe, "commit", "-m", "sync: update registered users database"],
                cwd=str(self.project_root),
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [git_exe, "push", "origin", TARGET_BRANCH],
                cwd=str(self.project_root),
                check=True,
                capture_output=True,
            )
            print("Cloud-D Git sync: pushed to remote via local git CLI.")
            return True
        except Exception as exc:
            print(f"Cloud-D local git push error: {exc}")
            return False

    def sync_after_registration(self) -> None:
        """Trigger asynchronous non-blocking sync to Git after user registration."""
        def _worker():
            with self._lock:
                state = self.export_state_from_db()
                self.save_local_state(state)
                # Try GitHub REST API first (works on Render and cloud)
                pushed = self.push_to_github(state)
                if not pushed:
                    # Fallback to local git CLI
                    self.push_to_local_git()

        threading.Thread(target=_worker, daemon=True, name="GitSyncWorker").start()

    def sync_on_startup(self) -> None:
        """Run on startup: restore state from GitHub API or local JSON file if SQLite is fresh."""
        with self._lock:
            # 1. Try fetching newest remote state from GitHub
            remote_state = self.pull_from_github()
            if remote_state:
                count = self.import_state_to_db(remote_state)
                print(f"Cloud-D startup: restored {count} accounts from GitHub remote state.")
                return

            # 2. Fallback: load from local data/cloud_d_state.json if exists
            local_state = self.load_local_state()
            if local_state:
                count = self.import_state_to_db(local_state)
                print(f"Cloud-D startup: restored {count} accounts from local state file.")

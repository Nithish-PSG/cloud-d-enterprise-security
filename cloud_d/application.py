from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from threading import RLock
from time import perf_counter

from .agents.attackers.credential_bot import CredentialBot
from .agents.attackers.flood_swarm import FloodSwarm
from .agents.attackers.ghost_user import GhostUser
from .agents.attackers.injector_x import InjectorX
from .agents.defenders.auth_sentinel import AuthSentinel
from .agents.defenders.behavior_watch import BehaviorWatch
from .agents.defenders.flow_guardian import FlowGuardian
from .agents.defenders.query_shield import QueryShield
from .cloud.enterprise_cloud import EnterpriseCloud
from .logic.decision_engine import DecisionEngine
from .storage import EncryptedSQLiteStore


VECTORS = ("auth", "flow", "query", "behavior")
VECTOR_NAMES = {
    "auth": ("Credential-Bot", "AuthSentinel", "Credential attacks"),
    "flow": ("FloodSwarm", "FlowGuardian", "DDoS / traffic floods"),
    "query": ("Injector-X", "QueryShield", "SQL injection"),
    "behavior": ("GhostUser", "BehaviorWatch", "Insider / anomalous behavior"),
}


class CloudDApplication:
    """Owns the simulation state shared by the local web interface."""

    def __init__(self):
        self.lock = RLock()
        self.threshold = .4
        self.intensity = "normal"
        self.active_vectors = set(VECTORS)
        self.storage = EncryptedSQLiteStore()
        self._reset_unlocked()

    @staticmethod
    def _password_hash(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)

    def register_user(self, details: dict) -> dict:
        email = str(details.get("email", "")).strip().casefold()
        username = str(details.get("username", "")).strip().casefold()
        name = username
        password = str(details.get("password", ""))
        role = str(details.get("role", ""))
        if role not in {"customer", "staff"}:
            raise ValueError("Choose Customer or Staff as the account type.")
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Enter a valid email address.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,29}", username):
            raise ValueError("Choose a username with 3–30 letters, numbers, dots, underscores, or hyphens; it must start with a letter or number.")
        if len(password) < 10 or len(password) > 1024:
            raise ValueError("Choose a password between 10 and 1024 characters.")

        registration_code = (
            os.environ.get("CLOUD_D_STAFF_REGISTRATION_CODE")
            or os.environ.get("CLOUD_D_STAFF_INVITE_CODE")
            or os.environ.get("CLOUD_D_ACCESS_PASSWORD", "")
        )
        staff_approved = role != "staff"
        if role == "staff":
            supplied_code = str(details.get("staff_registration_code", details.get("staff_invite_code", ""))).strip()
            if not registration_code:
                raise ValueError("Staff account creation is unavailable because the Staff Registration Code is not configured.")
            if not supplied_code:
                raise ValueError("A mandatory Staff Registration Code is required. Account creation is not possible without it.")
            if not hmac.compare_digest(supplied_code, registration_code):
                raise ValueError("The Staff Registration Code is incorrect. Account creation is not possible.")
            staff_approved = True
        status = "active"
        salt = secrets.token_bytes(16)
        existing = self.storage.get_user_by_email(email)
        existing_username = self.storage.get_user_credentials(username)
        if existing_username and (not existing or existing_username["user_id"] != existing["user_id"]):
            raise ValueError("That username is already in use. Choose another one.")
        if existing:
            if (
                role == "staff" and existing["role"] == "staff" and existing["status"] == "pending"
                and staff_approved and hmac.compare_digest(
                    self._password_hash(password, existing["password_salt"]), existing["password_hash"]
                )
            ):
                account = self.storage.activate_pending_staff(existing["user_id"], username)
                self.storage.ensure_default_folder(account)
                return self._start_session(account)
            raise ValueError("An account with that email already exists. Log in instead.")
        try:
            account = self.storage.create_user(
                uuid.uuid4().hex, email, username, name, role, status, salt, self._password_hash(password, salt)
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That email address or username is already in use.") from exc

        self.storage.ensure_default_folder(account)
        return self._start_session(account)

    def login_user(self, details: dict) -> dict:
        username = str(details.get("username", "")).strip().casefold()
        password = str(details.get("password", ""))
        if len(password) > 1024:
            raise ValueError("Username or password is incorrect.")
        account = self.storage.get_user_credentials(username)
        salt = account["password_salt"] if account else b"cloud-d-login-salt"
        expected = account["password_hash"] if account else b"\0" * 32
        supplied = self._password_hash(password, salt)
        if not hmac.compare_digest(supplied, expected) or account is None:
            raise ValueError("Username or password is incorrect.")
        if account["status"] != "active":
            raise ValueError("This account is inactive. Contact the Cloud-D administrator.")
        public = self.storage.get_user(account["user_id"])
        self.storage.ensure_default_folder(public)
        return self._start_session(public)

    def _start_session(self, user: dict) -> dict:
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + 12 * 60 * 60
        self.storage.create_session(token, user["id"], expires_at)
        return {"user": user, "session": token, "expires_at": expires_at}

    def resolve_session(self, token: str | None) -> dict | None:
        return self.storage.resolve_session(token)

    def revoke_session(self, token: str | None) -> None:
        self.storage.revoke_session(token)

    def list_folders(self, user: dict) -> list[dict]:
        return self.storage.list_folders(user)

    def create_folder(self, user: dict, name: str) -> dict:
        name = str(name or "").strip()
        if not name or len(name) > 64 or name in {".", ".."} or any(char in name for char in "/\\"):
            raise ValueError("Enter a folder name up to 64 characters without slashes.")
        try:
            return self.storage.create_folder(user, name)
        except sqlite3.IntegrityError as exc:
            raise ValueError("A folder with that name already exists in this storage area.") from exc

    @staticmethod
    def _node_for_user(user: dict) -> int:
        return 2 if user["role"] == "staff" else 3

    def _reset_unlocked(self):
        self.cloud = EnterpriseCloud(seed=42)
        self.attackers = [CredentialBot(), FloodSwarm(), InjectorX(), GhostUser()]
        self.defenders = [AuthSentinel(), FlowGuardian(), QueryShield(), BehaviorWatch()]
        for agent in [*self.attackers, *self.defenders]:
            agent.cloud = self.cloud
            agent.rng = self.cloud.rng
        self.engine = DecisionEngine(self.defenders, self.threshold)
        self.counts = {vector: {"scored": 0, "blocked": 0, "actions": 0, "last": 0.0} for vector in VECTORS}
        self.attack_log = []
        self.last_proposals = []
        self.latencies = []
        self.last_run_at = None
        self.has_run = False
        flood = next(agent for agent in self.attackers if agent.vector_id == "flow")
        flood.request_rate = {"normal": 5_000, "elevated": 7_000, "severe": 9_000}[self.intensity]
        self.storage.sync_nodes([node.to_dict() for node in self.cloud.nodes.values()])
        self._restore_uploads_unlocked()

    def _restore_uploads_unlocked(self) -> None:
        """Rehydrate the simulation from encrypted uploads without persisting run state."""
        for batch in self.storage.load_uploads():
            node_id = batch["node_id"]
            items = batch["items"]
            for item in items:
                if item["kind"] == "rows":
                    self.cloud.add_uploaded_rows(
                        node_id, item["filename"], item["rows"], item["content"], item["file_id"], item
                    )
                else:
                    self.cloud.add_uploaded_document(
                        node_id, item["filename"], item["content"], item["file_id"], item
                    )

    def reset(self):
        with self.lock:
            self._reset_unlocked()
            return self.get_state()

    def begin_new_run(self, config: dict | None = None) -> dict:
        with self.lock:
            if config:
                self.configure(config)
            self._reset_unlocked()
            return self.get_state()

    def configure(self, values: dict) -> None:
        with self.lock:
            if "threshold" in values:
                try:
                    self.threshold = max(.1, min(.9, float(values["threshold"])))
                except (TypeError, ValueError):
                    raise ValueError("Decision threshold must be a number between 0.10 and 0.90.")
                self.engine.threshold = self.threshold
            if "active_vectors" in values:
                requested = values["active_vectors"]
                if not isinstance(requested, list):
                    raise ValueError("Active vectors must be a list.")
                self.active_vectors = set(requested).intersection(VECTORS)
            if "intensity" in values:
                intensity = values["intensity"]
                if intensity not in {"normal", "elevated", "severe"}:
                    raise ValueError("Choose a valid attack intensity.")
                if intensity != self.intensity:
                    self.intensity = intensity
                    flood = next(agent for agent in self.attackers if agent.vector_id == "flow")
                    flood.request_rate = {"normal": 5_000, "elevated": 7_000, "severe": 9_000}[intensity]

    def simulate_round(self, config: dict | None = None) -> dict:
        with self.lock:
            if config:
                self.configure(config)
            if not self.active_vectors:
                raise ValueError("Select at least one attack vector.")
            if self.cloud.is_game_over():
                return self.get_state()

            self.cloud.advance_round()
            round_started = perf_counter()
            cloud_state = self.cloud.get_state()
            attacks = []
            for attacker in self.attackers:
                if attacker.vector_id not in self.active_vectors:
                    attacker.active = False
                    continue
                attack = attacker.decide(cloud_state)
                if attack is None:
                    continue
                self.cloud.register_attack(attack)
                attacks.append(attack)
                count = self.counts[attacker.vector_id]
                count["scored"] += 1
                count["last"] = attack.get("confidence", attack.get("payload_risk", attack["damage"] / 25 if attack["damage"] else .4))

            ranked, joint_actions = self.engine.joint_decision(attacks, self.cloud.get_state())
            self.last_proposals = ranked
            for proposal in ranked:
                vector = proposal["vector_id"]
                self.counts[vector]["last"] = proposal["utility"]
                if proposal in joint_actions:
                    self.counts[vector]["actions"] += 1

            for attack in attacks:
                blocker = self.engine.find_blocker(attack, joint_actions)
                related = next((proposal for proposal in ranked if attack["type"] in proposal["counters"]), None)
                decision = blocker or related
                vector = decision["vector_id"] if decision else attack["family"]
                if blocker:
                    self.cloud.block_attack(attack, blocker["agent"])
                    self.counts[vector]["blocked"] += 1
                    damage = 0
                else:
                    damage = attack["damage"]
                    if damage:
                        self.cloud.apply_damage(attack["target"], damage)
                        record_id = attack.get("record_id")
                        if record_id:
                            self.cloud.compromise_record(attack["target"], record_id)
                    self.cloud.log(
                        f"{attack['attacker']} passed defense on {attack['target_name']}" + (f" and caused {damage} damage" if damage else "; no direct compromise"),
                        "compromised" if damage else "info",
                    )

                search_nodes = attack.get("search", {}).get("nodes", 0)
                if decision:
                    search_nodes += decision.get("search", {}).get("nodes", 0)
                elapsed_ms = (perf_counter() - round_started) * 1000
                latency = max(12, round(16 + elapsed_ms + search_nodes * .7))
                self.latencies.append(latency)
                self.attack_log.append({
                    "round": self.cloud.round,
                    "attacker": attack["attacker"],
                    "tactic": attack.get("tactic", ""),
                    "attack_type": attack["type"],
                    "target": attack["target_name"],
                    "utility": decision["utility"] if decision else 0.0,
                    "defender": blocker["agent"] if blocker else "",
                    "action": blocker["action"] if blocker else (decision["action"] if decision else ""),
                    "blocked": bool(blocker),
                    "damage": damage,
                    "record_exposed": bool(not blocker and damage and attack.get("record_id")),
                    "record_id": attack.get("record_id", "") if not blocker and damage else "",
                    "payload": attack.get("payload", ""),
                    "rationale": blocker["rationale"] if blocker else (decision["rationale"] if decision else "No proposal exceeded the utility threshold."),
                    "search": attack.get("search") or (decision.get("search") if decision else None),
                })
            self.attack_log = self.attack_log[-500:]
            self.has_run = True
            self.last_run_at = datetime.now(timezone.utc).isoformat()
            return self.get_state()

    def upload_items(
        self,
        folder_id: str,
        items: list[dict],
        user: dict,
        duplicate_mode: str | None = None,
    ) -> dict:
        with self.lock:
            folder = self.storage.get_folder(folder_id, user)
            if folder is None:
                raise ValueError("Choose a folder in your assigned storage area.")
            node_id = int(folder["node_id"])
            node = self.cloud.get_node(node_id)
            if node is None:
                raise ValueError("Choose a valid cloud node.")
            if not items:
                raise ValueError("Choose at least one file to upload.")
            filenames = [str(item.get("filename", "")).casefold() for item in items]
            if len(filenames) != len(set(filenames)):
                raise ValueError("The selected files contain duplicate names. Upload one file per name at a time.")
            total_bytes = 0
            total_rows = 0
            for item in items:
                if item.get("kind") == "rows" and not item.get("rows"):
                    raise ValueError(f"{item.get('filename', 'The selected file')} contains no data rows.")
                if item.get("kind") == "document" and not item.get("content"):
                    raise ValueError(f"{item.get('filename', 'The selected file')} is empty.")
                if item.get("kind") not in {"rows", "document"}:
                    raise ValueError("This file could not be added to the simulated cloud.")
                if not item.get("filename"):
                    raise ValueError("Choose a file with a name.")
                content = item.get("content", b"")
                if not isinstance(content, (bytes, bytearray, memoryview)):
                    raise ValueError("File content must be binary data.")
                total_bytes += len(content)
                if total_bytes > 10 * 1024 * 1024:
                    raise ValueError("Selected files must total 10 MB or less.")
                if item["kind"] == "rows":
                    rows = item["rows"]
                    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                        raise ValueError("Structured uploads must contain rows with named fields.")
                    total_rows += len(rows)
                    if len(rows) > 10_000 or total_rows > 10_000:
                        raise ValueError("A single upload is limited to 10,000 data rows.")
            if duplicate_mode not in {None, "new_version", "replace"}:
                raise ValueError("Choose how to handle duplicate files.")
            stored = self.storage.save_upload_batch(
                node_id,
                folder_id,
                user["id"],
                user["role"],
                items,
                duplicate_mode=duplicate_mode,
            )
            loaded = 0
            for index, item in enumerate(items):
                file_info = stored[index]
                file_id = file_info["id"]
                if item["kind"] == "rows":
                    loaded += self.cloud.add_uploaded_rows(
                        node_id, item["filename"], item["rows"], item.get("content", b""), file_id, file_info
                    )
                elif item["kind"] == "document":
                    loaded += self.cloud.add_uploaded_document(
                        node_id, item["filename"], item["content"], file_id, file_info
                    )
                else:
                    raise ValueError("This file could not be added to the simulated cloud.")
            return {
                "loaded": loaded,
                "files": [item["filename"] for item in stored],
                "file_updates": [
                    {key: item[key] for key in ("filename", "version", "version_count", "created_at")}
                    for item in stored
                ],
                "folder": folder["name"],
                "state": self.get_state(user),
            }

    def get_file(self, file_id: str, user: dict) -> dict | None:
        with self.lock:
            return self.storage.get_file(file_id, user)

    def get_file_versions(self, logical_id: str, user: dict) -> list[dict]:
        with self.lock:
            return self.storage.get_file_versions(logical_id, user)

    def restore_backup_file(self, file_id: str, user: dict) -> dict | None:
        with self.lock:
            restored = self.storage.restore_backup_file(file_id, user)
            if restored is None:
                return None
            if restored.get("is_current"):
                node = self.cloud.get_node(int(restored["node_id"]))
                if node and not any(file["id"] == file_id for file in node.files):
                    item_info = {**restored, "logical_id": restored["logical_id"], "version_count": 1}
                    if restored["kind"] == "data":
                        self.cloud.add_uploaded_rows(
                            int(restored["node_id"]), restored["filename"], restored["rows"],
                            restored["content"], file_id, item_info,
                        )
                    else:
                        self.cloud.add_uploaded_document(
                            int(restored["node_id"]), restored["filename"], restored["content"], file_id, item_info
                        )
            return {"filename": restored["filename"], "restored": True, "state": self.get_state(user)}

    def verify_node_decryption(self, node_id: int) -> dict:
        with self.lock:
            node = self.cloud.get_node(node_id)
            if node is None:
                raise ValueError("Choose a valid cloud node.")
            verified = self.storage.verify_node_decryption(node_id)
            return {"node": node.name, "verified": verified, "encryption": "AES-256-GCM"}

    def reencrypt_node(self, node_id: int) -> dict:
        with self.lock:
            node = self.cloud.get_node(node_id)
            if node is None:
                raise ValueError("Choose a valid cloud node.")
            updated = self.storage.reencrypt_node(node_id)
            return {"node": node.name, "reencrypted": updated, "encryption": "AES-256-GCM"}

    def get_state(self, user: dict | None = None) -> dict:
        if user and user["role"] == "customer":
            return {
                "round": 0,
                "max_rounds": self.cloud.MAX_ROUNDS,
                "has_run": False,
                "game_over": False,
                "last_run_at": None,
                "threshold": self.threshold,
                "intensity": self.intensity,
                "active_vectors": [],
                "counts": {},
                "metrics": None,
                "nodes": [],
                "storage": self.storage.snapshot(user),
                "files": self.storage.list_files(user),
                "folders": self.storage.list_folders(user),
                "attack_log": [],
                "events": [],
                "proposals": [],
                "latency_ms": 0,
                "attackers": [],
                "defenders": [],
                "current_user": user,
            }
        report = self.cloud.final_report()
        state = {
            "round": self.cloud.round,
            "max_rounds": self.cloud.MAX_ROUNDS,
            "has_run": self.has_run,
            "game_over": self.cloud.is_game_over(),
            "last_run_at": self.last_run_at,
            "threshold": self.threshold,
            "intensity": self.intensity,
            "active_vectors": sorted(self.active_vectors),
            "counts": {key: dict(value) for key, value in self.counts.items()},
            "metrics": report,
            "nodes": report["node_health"],
            "storage": self.storage.snapshot(user),
            "files": self.storage.list_files(user) if user else [],
            "folders": self.storage.list_folders(user) if user else [],
            "attack_log": list(self.attack_log),
            "events": list(self.cloud.events[-60:]),
            "proposals": [dict(proposal) for proposal in self.last_proposals],
            "latency_ms": round(sum(self.latencies) / len(self.latencies)) if self.latencies else 0,
            "attackers": [
                {"name": agent.name, "vector_id": agent.vector_id, "active": agent.active, "search_nodes": agent.search_nodes,
                 "algorithm": "Minimax depth 2" if agent.vector_id == "auth" else "stochastic / rule heuristic"}
                for agent in self.attackers
            ],
            "defenders": [
                {"name": agent.name, "vector_id": agent.vector_id, "active": agent.active, "search_nodes": agent.search_nodes,
                 "algorithm": "Expectimax" if agent.vector_id == "query" else "utility heuristic"}
                for agent in self.defenders
            ],
        }
        if user:
            state["current_user"] = user
            # File names are exposed only through the permission-filtered file list.
            for node in state["nodes"]:
                node["files"] = []
                node["uploaded_files"] = []
        return state

    def close(self) -> None:
        self.storage.close()

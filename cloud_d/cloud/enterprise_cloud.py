from __future__ import annotations

import random
from typing import Any

from .cloud_node import CloudNode
from .data_record import DataRecord


class EnterpriseCloud:
    MAX_ROUNDS = 20

    def __init__(self, seed: int | None = 42):
        self.rng = random.Random(seed)
        self.round = 0
        self.events: list[dict[str, Any]] = []
        self.metrics = {
            "total_attacks": 0,
            "blocked_attacks": 0,
            "damage_taken": 0,
            "records_compromised": 0,
        }
        self.file_store: dict[str, dict[str, Any]] = {}
        self.file_counter = 0
        self.shared_intelligence: dict[str, int] = {}
        self.nodes = {
            0: CloudNode(0, "Auth Server", "auth", 70, [1, 3]),
            1: CloudNode(1, "API Gateway", "api", 60, [0, 2, 3]),
            2: CloudNode(2, "Primary DB", "db", 95, [1, 4]),
            3: CloudNode(3, "Customer DB", "customer", 90, [0, 1]),
            4: CloudNode(4, "Backup Server", "backup", 40, [2]),
        }
        self._populate_data()

    def _seed_records(self, node_id: int, prefix: str, record_type: str, count: int, low: int, high: int, owner):
        node = self.nodes[node_id]
        for i in range(count):
            if prefix == "TXN-":
                record_id = f"{prefix}{i * 1000:07d}"
            elif prefix == "CUST-":
                record_id = f"{prefix}{i:06d}"
            elif prefix in ("USER-", "CACHE-"):
                record_id = f"{prefix}{i:05d}"
            else:
                record_id = f"{prefix}{i}"
            node.store(DataRecord(record_id, record_type, self.rng.randint(low, high), owner(i), source="seeded"))

    def _populate_data(self) -> None:
        self._seed_records(0, "USER-", "credential", 500, 50, 100, lambda i: f"user_{i}")
        self._seed_records(1, "CACHE-", "cache", 200, 10, 30, lambda _i: "system")
        self._seed_records(2, "TXN-", "transaction", 500, 20, 100, lambda i: f"account_{i}")
        self._seed_records(3, "CUST-", "pii", 500, 40, 100, lambda i: f"customer_{i}")
        self._seed_records(4, "BACKUP-", "backup", 100, 70, 100, lambda _i: "system")

    def get_state(self) -> dict:
        return {
            "round": self.round,
            "max_rounds": self.MAX_ROUNDS,
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "metrics": dict(self.metrics),
            "intelligence": dict(self.shared_intelligence),
        }

    def get_node(self, node_id: int) -> CloudNode | None:
        return self.nodes.get(node_id)

    def get_node_by_role(self, role: str) -> CloudNode | None:
        return next((node for node in self.nodes.values() if node.role == role), None)

    def random_record(self, node_id: int) -> DataRecord | None:
        node = self.nodes.get(node_id)
        return node.random_protected_record(self.rng) if node else None

    def _clear_node_data(self, node: CloudNode) -> None:
        for file in node.files:
            self.file_store.pop(file["id"], None)
        node.clear_records()

    def _store_file(
        self,
        node: CloudNode,
        filename: str,
        content: bytes,
        kind: str,
        record_count: int,
        file_id: str | None = None,
        file_info: dict | None = None,
    ) -> dict:
        self.file_counter += 1
        file_id = file_id or f"FILE-{node.id}-{self.file_counter:06d}"
        info = file_info or {}
        superseded_ids = set(info.get("superseded_ids", []))
        if superseded_ids:
            node.files[:] = [file for file in node.files if file["id"] not in superseded_ids]
            for old_id in superseded_ids:
                self.file_store.pop(old_id, None)
        summary = {
            "id": file_id,
            "logical_id": info.get("logical_id", file_id),
            "version": int(info.get("version", 1)),
            "version_count": int(info.get("version_count", 1)),
            "created_at": info.get("created_at"),
            "owner_id": info.get("owner_id"),
            "access_role": info.get("access_role", "staff"),
            "folder_id": info.get("folder_id"),
            "filename": filename[:120],
            "size_bytes": len(content),
            "kind": kind,
            "record_count": record_count,
        }
        # File contents live in EncryptedSQLiteStore. Keep only public metadata here.
        self.file_store[file_id] = {**summary, "node_id": node.id}
        node.files.append(summary)
        if summary["filename"] not in node.uploaded_files:
            node.uploaded_files.append(summary["filename"])
        return summary

    @staticmethod
    def _remove_superseded_records(node: CloudNode, file_info: dict | None) -> None:
        superseded_ids = set((file_info or {}).get("superseded_ids", []))
        if not superseded_ids:
            return
        node.stored_data[:] = [
            record for record in node.stored_data
            if record.payload.get("file_id") not in superseded_ids
        ]
        node.files[:] = [file for file in node.files if file["id"] not in superseded_ids]
        node.uploaded_files[:] = list(dict.fromkeys(file["filename"] for file in node.files))
        node.total_records = len(node.stored_data)
        node.protected_records = sum(not record.is_compromised for record in node.stored_data)
        node.compromised_records = node.total_records - node.protected_records
        node.uploaded_records = sum(record.source == "uploaded" for record in node.stored_data)

    def get_file(self, file_id: str) -> dict[str, Any] | None:
        stored = self.file_store.get(file_id)
        return dict(stored) if stored else None

    def add_uploaded_rows(
        self,
        node_id: int,
        filename: str,
        rows: list[dict[str, Any]],
        content: bytes = b"",
        file_id: str | None = None,
        file_info: dict | None = None,
    ) -> int:
        node = self.nodes.get(node_id)
        if node is None:
            raise ValueError("Choose a valid cloud node.")
        if not rows:
            raise ValueError("The selected file contains no data rows.")
        if len(rows) > 10_000:
            raise ValueError("A single upload is limited to 10,000 records.")
        self._remove_superseded_records(node, file_info)
        filename = filename[:120]
        start = node.total_records + 1
        record_type = {"auth": "credential", "api": "cache", "db": "transaction", "customer": "pii", "backup": "backup"}[node.role]
        for offset, source_row in enumerate(rows):
            identifier = f"UPLOAD-{node_id}-{start + offset:06d}"
            value = self._importance_value(source_row)
            # Only derived simulation fields stay in process memory. Original rows are
            # stored encrypted by EncryptedSQLiteStore and are not copied onto records.
            node.store(DataRecord(identifier, record_type, value, "uploaded", source="uploaded", payload={"file_id": file_id or ""}))
        self._store_file(node, filename, content, "data", len(rows), file_id, file_info)
        self.log(f"Loaded {len(rows)} uploaded records into {node.name} ({filename})", "upload")
        return len(rows)

    def add_uploaded_document(
        self,
        node_id: int,
        filename: str,
        content: bytes,
        file_id: str | None = None,
        file_info: dict | None = None,
    ) -> int:
        node = self.nodes.get(node_id)
        if node is None:
            raise ValueError("Choose a valid cloud node.")
        if not filename:
            raise ValueError("Choose a file with a name.")
        if not content:
            raise ValueError(f"{filename} is empty.")
        self._remove_superseded_records(node, file_info)
        filename = filename[:120]
        identifier = f"UPLOAD-{node_id}-{node.total_records + 1:06d}"
        file = self._store_file(node, filename, content, "document", 1, file_id, file_info)
        metadata = {"filename": filename, "size_bytes": len(content), "kind": "document", "file_id": file["id"]}
        node.store(DataRecord(identifier, "document", 50, "uploaded", source="uploaded", payload=metadata))
        self.log(f"Loaded document {filename} into {node.name} ({len(content):,} bytes)", "upload")
        return 1

    @staticmethod
    def _importance_value(row: dict[str, Any]) -> int:
        for key, value in row.items():
            if str(key).strip().lower() in {"importance", "value", "risk", "sensitivity", "score"}:
                try:
                    return max(0, min(100, int(float(value))))
                except (TypeError, ValueError):
                    continue
        return 50

    def register_attack(self, attack: dict) -> None:
        self.metrics["total_attacks"] += 1
        node = self.nodes.get(attack["target"])
        if node:
            node.malicious_traffic += 1
            if attack.get("request_rate"):
                node.current_traffic = attack["request_rate"]
        attack_type = attack["type"]
        self.shared_intelligence[attack_type] = self.shared_intelligence.get(attack_type, 0) + 1
        self.log(f"{attack['attacker']} → {attack['target_name']} · {attack_type}", "attack")

    def block_attack(self, attack: dict, defender_name: str) -> None:
        self.metrics["blocked_attacks"] += 1
        self.log(f"{defender_name} blocked {attack['type']} on {attack['target_name']}", "blocked")

    def apply_damage(self, node_id: int, amount: int) -> int:
        node = self.nodes[node_id]
        actual = node.take_damage(amount)
        self.metrics["damage_taken"] += actual
        if actual:
            self.log(f"{node.name} took {actual} damage (health {node.health})", "compromised")
        return actual

    def compromise_record(self, node_id: int, record_id: str) -> bool:
        node = self.nodes[node_id]
        if node.compromise_record(record_id):
            self.metrics["records_compromised"] += 1
            self.log(f"Record {record_id} exposed on {node.name}", "compromised")
            return True
        return False

    def log(self, message: str, kind: str = "info") -> None:
        self.events.append({"round": self.round, "message": message, "kind": kind})
        if len(self.events) > 500:
            del self.events[:-500]

    def advance_round(self) -> None:
        self.round += 1

    def is_game_over(self) -> bool:
        dead_nodes = sum(1 for node in self.nodes.values() if node.is_compromised())
        return dead_nodes >= 3 or self.round >= self.MAX_ROUNDS

    def final_report(self) -> dict:
        nodes = list(self.nodes.values())
        total_records = sum(node.total_records for node in nodes)
        protected = sum(node.protected_records for node in nodes)
        compromised = sum(node.compromised_records for node in nodes)
        total_attacks = self.metrics["total_attacks"]
        blocked = self.metrics["blocked_attacks"]
        return {
            "rounds": self.round,
            "total_attacks": total_attacks,
            "blocked": blocked,
            "block_rate": round(blocked / total_attacks * 100, 1) if total_attacks else 0.0,
            "total_records": total_records,
            "protected": protected,
            "compromised": compromised,
            "protection_rate": round(protected / total_records * 100, 3) if total_records else 100.0,
            "damage_taken": self.metrics["damage_taken"],
            "node_health": [node.to_dict() for node in nodes],
        }

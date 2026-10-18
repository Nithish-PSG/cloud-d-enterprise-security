from __future__ import annotations

from .data_record import DataRecord


class CloudNode:
    def __init__(self, node_id: int, name: str, role: str, data_value: int, connections: list[int]):
        self.id = node_id
        self.name = name
        self.role = role
        self.health = 100
        self.data_value = data_value
        self.connections = connections
        self.current_traffic = 0
        self.malicious_traffic = 0
        self.stored_data: list[DataRecord] = []
        self.total_records = 0
        self.protected_records = 0
        self.compromised_records = 0
        self.uploaded_records = 0
        self.uploaded_files: list[str] = []
        self.files: list[dict] = []

    def store(self, record: DataRecord) -> None:
        self.stored_data.append(record)
        self.total_records += 1
        self.protected_records += 1
        if record.source == "uploaded":
            self.uploaded_records += 1

    def clear_records(self) -> None:
        self.stored_data.clear()
        self.total_records = 0
        self.protected_records = 0
        self.compromised_records = 0
        self.uploaded_records = 0
        self.uploaded_files.clear()
        self.files.clear()

    def compromise_record(self, record_id: str) -> bool:
        for record in self.stored_data:
            if record.id == record_id and not record.is_compromised:
                record.compromise()
                self.protected_records -= 1
                self.compromised_records += 1
                return True
        return False

    def random_protected_record(self, rng) -> DataRecord | None:
        available = [record for record in self.stored_data if not record.is_compromised]
        return rng.choice(available) if available else None

    def take_damage(self, amount: int) -> int:
        before = self.health
        self.health = max(0, self.health - max(0, amount))
        return before - self.health

    def heal(self, amount: int) -> int:
        self.health = min(100, self.health + max(0, amount))
        return self.health

    def is_compromised(self) -> bool:
        return self.health == 0

    def protection_rate(self) -> float:
        return (self.protected_records / self.total_records * 100) if self.total_records else 100.0

    def status(self) -> str:
        if self.health == 0:
            return "COMPROMISED"
        if self.health > 70:
            return "HEALTHY"
        if self.health > 30:
            return "DAMAGED"
        return "CRITICAL"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "health": self.health,
            "status": self.status(),
            "data_value": self.data_value,
            "connections": self.connections,
            "current_traffic": self.current_traffic,
            "malicious_traffic": self.malicious_traffic,
            "total_records": self.total_records,
            "protected_records": self.protected_records,
            "compromised_records": self.compromised_records,
            "uploaded_records": self.uploaded_records,
            "uploaded_files": list(self.uploaded_files),
            "files": [dict(file) for file in self.files],
            "protection_rate": round(self.protection_rate(), 3),
        }

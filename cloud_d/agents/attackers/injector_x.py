from ..base_agent import BaseAgent


class InjectorX(BaseAgent):
    def __init__(self):
        super().__init__("Injector-X", "query")
        self.payloads = [
            ("' OR 1=1--", .78),
            ("'; DROP TABLE transactions;--", 1.0),
            ("UNION SELECT * FROM customers--", .90),
        ]

    def decide(self, state):
        self.active = False
        node = next((item for item in state["nodes"] if item["role"] == "db" and item["health"] > 0), None)
        if node is None:
            return None
        self.active = True
        payload, risk = self.rng.choice(self.payloads)
        record = self.cloud.random_record(node["id"])
        return {
            "attacker": self.name,
            "type": "sql_injection",
            "family": "query",
            "target": node["id"],
            "target_name": node["name"],
            "damage": 20,
            "payload": payload,
            "payload_risk": risk,
            "record_id": record.id if record else None,
        }

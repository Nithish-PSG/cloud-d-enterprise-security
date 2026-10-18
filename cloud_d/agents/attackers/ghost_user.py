from ..base_agent import BaseAgent


class GhostUser(BaseAgent):
    def __init__(self):
        super().__init__("GhostUser", "behavior")

    def decide(self, state):
        self.active = False
        node = next((item for item in state["nodes"] if item["role"] == "customer" and item["health"] > 0), None)
        if node is None:
            return None
        self.active = True
        harvested = self.rng.random() < .3
        record = self.cloud.random_record(node["id"])
        return {
            "attacker": self.name,
            "type": "phishing",
            "family": "behavior",
            "target": node["id"],
            "target_name": node["name"],
            "damage": 25 if harvested else 0,
            "credential_harvested": harvested,
            "record_id": record.id if record else None,
        }

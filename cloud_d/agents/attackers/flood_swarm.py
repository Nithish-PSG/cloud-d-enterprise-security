from ..base_agent import BaseAgent


class FloodSwarm(BaseAgent):
    def __init__(self):
        super().__init__("FloodSwarm", "flow")
        self.request_rate = 5_000

    def decide(self, state):
        self.active = False
        node = next((item for item in state["nodes"] if item["role"] == "api" and item["health"] > 0), None)
        if node is None:
            return None
        self.active = True
        self.request_rate += self.rng.randint(1_000, 4_000)
        damage = 15 if self.request_rate > 10_000 else 5
        record = self.cloud.random_record(node["id"])
        return {
            "attacker": self.name,
            "type": "ddos",
            "family": "flow",
            "target": node["id"],
            "target_name": node["name"],
            "damage": damage,
            "request_rate": self.request_rate,
            "record_id": record.id if record else None,
        }

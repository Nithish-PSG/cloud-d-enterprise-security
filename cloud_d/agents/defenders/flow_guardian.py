from ..base_agent import BaseAgent


class FlowGuardian(BaseAgent):
    def __init__(self):
        super().__init__("FlowGuardian", "flow")

    def propose(self, attacks, _state):
        attack = next((item for item in attacks if item["type"] == "ddos"), None)
        self.active = attack is not None
        if attack is None:
            return None
        return {
            "agent": self.name,
            "vector_id": self.vector_id,
            "action": "rate_limit + absorb traffic",
            "target": attack["target"],
            "utility": round(min(1.0, attack["damage"] / 15), 2),
            "counters": ["ddos"],
            "attack_type": attack["type"],
            "rationale": f"Traffic rate reached {attack['request_rate']:,} simulated requests/s.",
        }

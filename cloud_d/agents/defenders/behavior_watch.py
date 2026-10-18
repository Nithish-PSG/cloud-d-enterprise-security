from ..base_agent import BaseAgent


class BehaviorWatch(BaseAgent):
    def __init__(self):
        super().__init__("BehaviorWatch", "behavior")

    def propose(self, attacks, state):
        attack = next((item for item in attacks if item["type"] == "phishing"), None)
        self.active = attack is not None
        if attack is None:
            return None
        prior = max(0, state["intelligence"].get("phishing", 1) - 1)
        bonus = min(.12, prior * .015)
        utility = min(1.0, (attack["damage"] / 25 if attack["damage"] else .4) + bonus)
        return {
            "agent": self.name,
            "vector_id": self.vector_id,
            "action": "revoke session + quarantine",
            "target": attack["target"],
            "utility": round(utility, 2),
            "counters": ["phishing"],
            "attack_type": attack["type"],
            "rationale": "Credential-harvest signal observed." if attack["damage"] else "Anomalous user pattern flagged.",
        }

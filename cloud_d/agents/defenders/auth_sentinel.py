from ..base_agent import BaseAgent


class AuthSentinel(BaseAgent):
    def __init__(self):
        super().__init__("AuthSentinel", "auth")

    def propose(self, attacks, state):
        attack = next((item for item in attacks if item["family"] == "auth"), None)
        self.active = attack is not None
        if attack is None:
            return None
        prior = max(0, state["intelligence"].get(attack["type"], 1) - 1)
        bonus = min(.12, prior * .015)
        utility = min(1.0, (attack["damage"] / 10 if attack["damage"] else .4) + bonus)
        response = "revoke_token" if attack["type"] == "token_replay" else "block_ip + lock account"
        return {
            "agent": self.name,
            "vector_id": self.vector_id,
            "action": response,
            "target": attack["target"],
            "utility": round(utility, 2),
            "counters": ["brute_force", "credential_stuffing", "token_replay"],
            "attack_type": attack["type"],
            "rationale": f"Credential signal with shared-intelligence bonus {bonus:.2f}.",
        }

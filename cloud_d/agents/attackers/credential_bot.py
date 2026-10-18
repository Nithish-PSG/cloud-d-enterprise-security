from __future__ import annotations

from ..base_agent import BaseAgent
from ...logic.search import minimax


class CredentialBot(BaseAgent):
    """Minimax attacker: maximize expected impact after a modeled defender reply."""

    def __init__(self):
        super().__init__("Credential-Bot", "auth")
        self.attempts = 0

    def decide(self, state):
        self.active = False
        auth = next((node for node in state["nodes"] if node["role"] == "auth" and node["health"] > 0), None)
        api = next((node for node in state["nodes"] if node["role"] == "api" and node["health"] > 0), None)
        if auth is None:
            return None
        self.active = True
        self.attempts += 15
        candidates = [
            {
                "type": "brute_force", "family": "auth", "tactic": "password spray",
                "target": auth["id"], "target_name": auth["name"], "damage": 8,
                "defender_replies": [("block_ip", .92), ("lock_account", .83), ("monitor", .12)],
            },
            {
                "type": "credential_stuffing", "family": "auth", "tactic": "credential stuffing",
                "target": auth["id"], "target_name": auth["name"], "damage": 7,
                "defender_replies": [("block_ip", .68), ("lock_account", .86), ("monitor", .10)],
            },
        ]
        if api is not None:
            candidates.append({
                "type": "token_replay", "family": "auth", "tactic": "stolen-token replay",
                "target": api["id"], "target_name": api["name"], "damage": 6,
                "defender_replies": [("revoke_token", .88), ("block_ip", .53), ("monitor", .12)],
            })

        root = {
            "kind": "max",
            "children": [
                {
                    "kind": "min", "action": attack,
                    "children": [
                        {"kind": "leaf", "value": attack["damage"] * (1 - coverage), "action": response}
                        for response, coverage in attack["defender_replies"]
                    ],
                }
                for attack in candidates
            ],
        }
        value, chosen, self.search_nodes = minimax(root, depth=2)
        confidence = min(.9, self.attempts / 100)
        attack = {key: value for key, value in chosen.items() if key != "defender_replies"}
        attack["confidence"] = round(confidence, 2)
        attack["damage"] = attack["damage"] if self.rng.random() < confidence else 0
        attack["record_id"] = self.cloud.random_record(attack["target"])
        attack["search"] = {"algorithm": "Minimax", "depth": 2, "nodes": self.search_nodes, "predicted_damage": round(value, 2)}
        attack["attacker"] = self.name
        return attack

from ..base_agent import BaseAgent
from ...logic.search import expectimax


class QueryShield(BaseAgent):
    """Choose a response by maximizing expected protection over uncertain outcomes."""

    def __init__(self):
        super().__init__("QueryShield", "query")

    def propose(self, attacks, _state):
        attack = next((item for item in attacks if item["type"] == "sql_injection"), None)
        self.active = attack is not None
        if attack is None:
            return None
        risk = attack["payload_risk"]
        bypass = .22 - risk * .12
        choices = [
            {
                "action": "sanitize query",
                "children": [
                    {"probability": 1 - bypass, "value": .98},
                    {"probability": bypass, "value": .52},
                ],
            },
            {
                "action": "reject query",
                "children": [
                    {"probability": .97 - (1 - risk) * .03, "value": .87},
                    {"probability": .03 + (1 - risk) * .03, "value": .18},
                ],
            },
            {
                "action": "monitor query",
                "children": [
                    {"probability": .3, "value": .92},
                    {"probability": .7, "value": .08},
                ],
            },
        ]
        tree = {
            "kind": "max",
            "children": [
                {"kind": "chance", "action": choice["action"], "children": choice["children"]}
                for choice in choices
            ],
        }
        best_value, best_action, self.search_nodes = expectimax(tree)
        return {
            "agent": self.name,
            "vector_id": self.vector_id,
            "action": best_action,
            "target": attack["target"],
            "utility": round(best_value, 2),
            "counters": ["sql_injection"],
            "attack_type": attack["type"],
            "rationale": f"Expectimax expected protection {best_value:.2f}; payload risk {risk:.2f}.",
            "search": {"algorithm": "Expectimax", "nodes": self.search_nodes},
        }

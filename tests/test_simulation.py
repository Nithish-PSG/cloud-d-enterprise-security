import unittest

from cloud_d.agents.attackers.credential_bot import CredentialBot
from cloud_d.agents.attackers.flood_swarm import FloodSwarm
from cloud_d.agents.attackers.ghost_user import GhostUser
from cloud_d.agents.attackers.injector_x import InjectorX
from cloud_d.agents.defenders.auth_sentinel import AuthSentinel
from cloud_d.agents.defenders.behavior_watch import BehaviorWatch
from cloud_d.agents.defenders.flow_guardian import FlowGuardian
from cloud_d.agents.defenders.query_shield import QueryShield
from cloud_d.cloud.enterprise_cloud import EnterpriseCloud
from cloud_d.logic.decision_engine import DecisionEngine
from cloud_d.logic.search import expectimax, minimax


class TestSimulationLogic(unittest.TestCase):
    def test_minimax_search(self):
        tree = {
            "kind": "max",
            "children": [
                {
                    "kind": "min",
                    "action": "move_a",
                    "children": [
                        {"kind": "leaf", "value": 10, "action": "leaf_1"},
                        {"kind": "leaf", "value": 5, "action": "leaf_2"},
                    ],
                },
                {
                    "kind": "min",
                    "action": "move_b",
                    "children": [
                        {"kind": "leaf", "value": 20, "action": "leaf_3"},
                        {"kind": "leaf", "value": 15, "action": "leaf_4"},
                    ],
                },
            ],
        }
        val, action, visited = minimax(tree, depth=2)
        self.assertEqual(val, 15.0)
        self.assertEqual(action, "move_b")
        self.assertGreater(visited, 0)

    def test_expectimax_search(self):
        tree = {
            "kind": "max",
            "children": [
                {
                    "kind": "chance",
                    "action": "inspect_strict",
                    "children": [
                        {"kind": "leaf", "value": 100, "probability": 0.8},
                        {"kind": "leaf", "value": 0, "probability": 0.2},
                    ],
                },
                {
                    "kind": "chance",
                    "action": "inspect_lenient",
                    "children": [
                        {"kind": "leaf", "value": 50, "probability": 0.5},
                        {"kind": "leaf", "value": 50, "probability": 0.5},
                    ],
                },
            ],
        }
        val, action, visited = expectimax(tree)
        self.assertEqual(val, 80.0)
        self.assertEqual(action, "inspect_strict")
        self.assertGreater(visited, 0)

    def test_enterprise_cloud_initial_state(self):
        cloud = EnterpriseCloud(seed=42)
        self.assertEqual(len(cloud.nodes), 5)
        self.assertEqual(cloud.round, 0)
        self.assertFalse(cloud.is_game_over())
        self.assertIn("Auth Server", [n.name for n in cloud.nodes.values()])

    def test_simulation_reproducibility(self):
        cloud1 = EnterpriseCloud(seed=12345)
        cloud2 = EnterpriseCloud(seed=12345)

        attacks1 = []
        for _ in range(5):
            cloud1.advance_round()
            attacks1.append(cloud1.rng.randint(1, 100))

        attacks2 = []
        for _ in range(5):
            cloud2.advance_round()
            attacks2.append(cloud2.rng.randint(1, 100))

        self.assertEqual(attacks1, attacks2)

    def test_agents_and_decision_engine(self):
        cloud = EnterpriseCloud(seed=42)
        attackers = [CredentialBot(), FloodSwarm(), InjectorX(), GhostUser()]
        defenders = [AuthSentinel(), FlowGuardian(), QueryShield(), BehaviorWatch()]
        engine = DecisionEngine(defenders=defenders, threshold=0.3)

        for agent in [*attackers, *defenders]:
            agent.cloud = cloud
            agent.rng = cloud.rng

        cloud.advance_round()
        cloud_state = cloud.get_state()
        attacks = [a.decide(cloud_state) for a in attackers if a.decide(cloud_state)]
        self.assertEqual(len(attacks), 4)

        for atk in attacks:
            cloud.register_attack(atk)

        ranked, joint_actions = engine.joint_decision(attacks, cloud_state)
        self.assertIsInstance(ranked, list)
        self.assertIsInstance(joint_actions, list)

        # Applying damage should properly decrement health and track damage
        applied = cloud.apply_damage(node_id=0, amount=10)
        self.assertEqual(applied, 10)
        self.assertEqual(cloud.nodes[0].health, 90)
        self.assertEqual(cloud.metrics["damage_taken"], 10)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
from threading import RLock
from time import perf_counter

from .agents.attackers.credential_bot import CredentialBot
from .agents.attackers.flood_swarm import FloodSwarm
from .agents.attackers.ghost_user import GhostUser
from .agents.attackers.injector_x import InjectorX
from .agents.defenders.auth_sentinel import AuthSentinel
from .agents.defenders.behavior_watch import BehaviorWatch
from .agents.defenders.flow_guardian import FlowGuardian
from .agents.defenders.query_shield import QueryShield
from .cloud.enterprise_cloud import EnterpriseCloud
from .logic.decision_engine import DecisionEngine


VECTORS = ("auth", "flow", "query", "behavior")
VECTOR_NAMES = {
    "auth": ("Credential-Bot", "AuthSentinel", "Credential attacks"),
    "flow": ("FloodSwarm", "FlowGuardian", "DDoS / traffic floods"),
    "query": ("Injector-X", "QueryShield", "SQL injection"),
    "behavior": ("GhostUser", "BehaviorWatch", "Insider / anomalous behavior"),
}


class CloudDApplication:
    """Owns the simulation state shared by the local web interface."""

    def __init__(self):
        self.lock = RLock()
        self.threshold = .4
        self.intensity = "normal"
        self.active_vectors = set(VECTORS)
        self.upload_batches = []
        self._reset_unlocked()

    def _reset_unlocked(self):
        self.cloud = EnterpriseCloud(seed=42)
        self.attackers = [CredentialBot(), FloodSwarm(), InjectorX(), GhostUser()]
        self.defenders = [AuthSentinel(), FlowGuardian(), QueryShield(), BehaviorWatch()]
        for agent in [*self.attackers, *self.defenders]:
            agent.cloud = self.cloud
            agent.rng = self.cloud.rng
        self.engine = DecisionEngine(self.defenders, self.threshold)
        self.counts = {vector: {"scored": 0, "blocked": 0, "actions": 0, "last": 0.0} for vector in VECTORS}
        self.attack_log = []
        self.last_proposals = []
        self.latencies = []
        self.last_run_at = None
        self.has_run = False
        flood = next(agent for agent in self.attackers if agent.vector_id == "flow")
        flood.request_rate = {"normal": 5_000, "elevated": 7_000, "severe": 9_000}[self.intensity]

    def reset(self):
        with self.lock:
            self.upload_batches = []
            self._reset_unlocked()
            return self.get_state()

    def begin_new_run(self, config: dict | None = None) -> dict:
        with self.lock:
            if config:
                self.configure(config)
            batches = deepcopy(self.upload_batches)
            self._reset_unlocked()
            self.upload_batches = batches
            for batch in batches:
                for index, item in enumerate(batch["items"]):
                    replace_node = batch["replace"] and index == 0
                    if item["kind"] == "rows":
                        self.cloud.add_uploaded_rows(batch["node_id"], item["filename"], item["rows"], replace_node, item.get("content", b""))
                    else:
                        self.cloud.add_uploaded_document(batch["node_id"], item["filename"], item["content"], replace_node)
            return self.get_state()

    def configure(self, values: dict) -> None:
        with self.lock:
            if "threshold" in values:
                try:
                    self.threshold = max(.1, min(.9, float(values["threshold"])))
                except (TypeError, ValueError):
                    raise ValueError("Decision threshold must be a number between 0.10 and 0.90.")
                self.engine.threshold = self.threshold
            if "active_vectors" in values:
                requested = values["active_vectors"]
                if not isinstance(requested, list):
                    raise ValueError("Active vectors must be a list.")
                self.active_vectors = set(requested).intersection(VECTORS)
            if "intensity" in values:
                intensity = values["intensity"]
                if intensity not in {"normal", "elevated", "severe"}:
                    raise ValueError("Choose a valid attack intensity.")
                if intensity != self.intensity:
                    self.intensity = intensity
                    flood = next(agent for agent in self.attackers if agent.vector_id == "flow")
                    flood.request_rate = {"normal": 5_000, "elevated": 7_000, "severe": 9_000}[intensity]

    def simulate_round(self, config: dict | None = None) -> dict:
        with self.lock:
            if config:
                self.configure(config)
            if not self.active_vectors:
                raise ValueError("Select at least one attack vector.")
            if self.cloud.is_game_over():
                return self.get_state()

            self.cloud.advance_round()
            round_started = perf_counter()
            cloud_state = self.cloud.get_state()
            attacks = []
            for attacker in self.attackers:
                if attacker.vector_id not in self.active_vectors:
                    attacker.active = False
                    continue
                attack = attacker.decide(cloud_state)
                if attack is None:
                    continue
                self.cloud.register_attack(attack)
                attacks.append(attack)
                count = self.counts[attacker.vector_id]
                count["scored"] += 1
                count["last"] = attack.get("confidence", attack.get("payload_risk", attack["damage"] / 25 if attack["damage"] else .4))

            ranked, joint_actions = self.engine.joint_decision(attacks, self.cloud.get_state())
            self.last_proposals = ranked
            for proposal in ranked:
                vector = proposal["vector_id"]
                self.counts[vector]["last"] = proposal["utility"]
                if proposal in joint_actions:
                    self.counts[vector]["actions"] += 1

            for attack in attacks:
                blocker = self.engine.find_blocker(attack, joint_actions)
                related = next((proposal for proposal in ranked if attack["type"] in proposal["counters"]), None)
                decision = blocker or related
                vector = decision["vector_id"] if decision else attack["family"]
                if blocker:
                    self.cloud.block_attack(attack, blocker["agent"])
                    self.counts[vector]["blocked"] += 1
                    damage = 0
                else:
                    damage = attack["damage"]
                    if damage:
                        self.cloud.apply_damage(attack["target"], damage)
                        record_id = attack.get("record_id")
                        if record_id:
                            self.cloud.compromise_record(attack["target"], record_id)
                    self.cloud.log(
                        f"{attack['attacker']} passed defense on {attack['target_name']}" + (f" and caused {damage} damage" if damage else "; no direct compromise"),
                        "compromised" if damage else "info",
                    )

                search_nodes = attack.get("search", {}).get("nodes", 0)
                if decision:
                    search_nodes += decision.get("search", {}).get("nodes", 0)
                elapsed_ms = (perf_counter() - round_started) * 1000
                latency = max(12, round(16 + elapsed_ms + search_nodes * .7))
                self.latencies.append(latency)
                self.attack_log.append({
                    "round": self.cloud.round,
                    "attacker": attack["attacker"],
                    "tactic": attack.get("tactic", ""),
                    "attack_type": attack["type"],
                    "target": attack["target_name"],
                    "utility": decision["utility"] if decision else 0.0,
                    "defender": blocker["agent"] if blocker else "",
                    "action": blocker["action"] if blocker else (decision["action"] if decision else ""),
                    "blocked": bool(blocker),
                    "damage": damage,
                    "record_exposed": bool(not blocker and damage and attack.get("record_id")),
                    "record_id": attack.get("record_id", "") if not blocker and damage else "",
                    "payload": attack.get("payload", ""),
                    "rationale": blocker["rationale"] if blocker else (decision["rationale"] if decision else "No proposal exceeded the utility threshold."),
                    "search": attack.get("search") or (decision.get("search") if decision else None),
                })
            self.attack_log = self.attack_log[-500:]
            self.has_run = True
            self.last_run_at = datetime.now(timezone.utc).isoformat()
            return self.get_state()

    def upload_items(self, node_id: int, items: list[dict], replace: bool = False) -> dict:
        with self.lock:
            node = self.cloud.get_node(node_id)
            if node is None:
                raise ValueError("Choose a valid cloud node.")
            if not items:
                raise ValueError("Choose at least one file to upload.")
            for item in items:
                if item.get("kind") == "rows" and not item.get("rows"):
                    raise ValueError(f"{item.get('filename', 'The selected file')} contains no data rows.")
                if item.get("kind") == "document" and not item.get("content"):
                    raise ValueError(f"{item.get('filename', 'The selected file')} is empty.")
                if item.get("kind") not in {"rows", "document"}:
                    raise ValueError("This file could not be added to the simulated cloud.")
            loaded = 0
            for index, item in enumerate(items):
                replace_node = replace and index == 0
                if item["kind"] == "rows":
                    loaded += self.cloud.add_uploaded_rows(node_id, item["filename"], item["rows"], replace_node, item.get("content", b""))
                elif item["kind"] == "document":
                    loaded += self.cloud.add_uploaded_document(node_id, item["filename"], item["content"], replace_node)
                else:
                    raise ValueError("This file could not be added to the simulated cloud.")
            self.upload_batches.append({"node_id": node_id, "items": deepcopy(items), "replace": replace})
            return {
                "loaded": loaded,
                "files": [item["filename"] for item in items],
                "node": node.name,
                "state": self.get_state(),
            }

    def get_file(self, file_id: str) -> dict | None:
        with self.lock:
            return self.cloud.get_file(file_id)

    def upload_rows(self, node_id: int, filename: str, rows: list[dict], replace: bool = False) -> dict:
        return self.upload_items(node_id, [{"kind": "rows", "filename": filename, "rows": rows}], replace)

    def get_state(self) -> dict:
        report = self.cloud.final_report()
        return {
            "round": self.cloud.round,
            "max_rounds": self.cloud.MAX_ROUNDS,
            "has_run": self.has_run,
            "game_over": self.cloud.is_game_over(),
            "last_run_at": self.last_run_at,
            "threshold": self.threshold,
            "intensity": self.intensity,
            "active_vectors": sorted(self.active_vectors),
            "counts": {key: dict(value) for key, value in self.counts.items()},
            "metrics": report,
            "nodes": report["node_health"],
            "attack_log": list(self.attack_log),
            "events": list(self.cloud.events[-60:]),
            "proposals": [dict(proposal) for proposal in self.last_proposals],
            "latency_ms": round(sum(self.latencies) / len(self.latencies)) if self.latencies else 0,
            "attackers": [
                {"name": agent.name, "vector_id": agent.vector_id, "active": agent.active, "search_nodes": agent.search_nodes,
                 "algorithm": "Minimax depth 2" if agent.vector_id == "auth" else "stochastic / rule heuristic"}
                for agent in self.attackers
            ],
            "defenders": [
                {"name": agent.name, "vector_id": agent.vector_id, "active": agent.active, "search_nodes": agent.search_nodes,
                 "algorithm": "Expectimax" if agent.vector_id == "query" else "utility heuristic"}
                for agent in self.defenders
            ],
        }

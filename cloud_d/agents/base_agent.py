class BaseAgent:
    def __init__(self, name: str, vector_id: str):
        self.name = name
        self.vector_id = vector_id
        self.active = False
        self.search_nodes = 0
        self.cloud = None
        self.rng = None

    def decide(self, state):
        raise NotImplementedError("Attacker agents must implement decide().")

    def propose(self, attacks, state):
        raise NotImplementedError("Defender agents must implement propose().")

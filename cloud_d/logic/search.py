from __future__ import annotations


def minimax(node: dict, depth: int, alpha: float = float("-inf"), beta: float = float("inf"), stats: dict | None = None):
    """Evaluate a small deterministic max/min tree with alpha-beta pruning.

    Returns (value, root_action, visited_node_count).
    """
    stats = stats if stats is not None else {"nodes": 0}
    stats["nodes"] += 1
    if depth <= 0 or node.get("kind") == "leaf" or not node.get("children"):
        return float(node.get("value", 0)), node.get("action"), stats["nodes"]

    if node["kind"] == "max":
        best_value = float("-inf")
        best_action = None
        for child in node["children"]:
            value, _, _ = minimax(child, depth - 1, alpha, beta, stats)
            if value > best_value:
                best_value = value
                best_action = child.get("action")
            alpha = max(alpha, best_value)
            if beta <= alpha:
                break
        return best_value, best_action, stats["nodes"]

    best_value = float("inf")
    best_action = None
    for child in node["children"]:
        value, action, _ = minimax(child, depth - 1, alpha, beta, stats)
        if value < best_value:
            best_value = value
            best_action = action
        beta = min(beta, best_value)
        if beta <= alpha:
            break
    return best_value, best_action, stats["nodes"]


def expectimax(node: dict, stats: dict | None = None):
    """Evaluate max and probability-weighted chance nodes.

    Returns (expected_value, selected_root_action, visited_node_count).
    """
    stats = stats if stats is not None else {"nodes": 0}
    stats["nodes"] += 1
    kind = node.get("kind", "leaf")
    if kind == "leaf":
        return float(node.get("value", 0)), node.get("action"), stats["nodes"]
    if kind == "chance":
        value = 0.0
        probability_total = 0.0
        for child in node.get("children", []):
            probability = float(child.get("probability", 0))
            child_value, _, _ = expectimax(child, stats)
            value += probability * child_value
            probability_total += probability
        if probability_total <= 0:
            return 0.0, node.get("action"), stats["nodes"]
        return value / probability_total, node.get("action"), stats["nodes"]

    best_value = float("-inf")
    best_action = None
    for child in node.get("children", []):
        value, _, _ = expectimax(child, stats)
        if value > best_value:
            best_value = value
            best_action = child.get("action")
    return best_value, best_action, stats["nodes"]

"""Defensive analysis of synthetic AWS-style resource relationship graphs."""
from collections import deque
from copy import deepcopy

VALID_KINDS = {"internet", "user", "role", "compute", "bucket", "database", "secret"}
SENSITIVE = {"bucket", "database", "secret"}


def validate_environment(environment):
    if not isinstance(environment, dict):
        raise ValueError("Environment must be an object")
    nodes, edges = environment.get("nodes"), environment.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("nodes and edges must be lists")
    if len(nodes) > 250 or len(edges) > 2000:
        raise ValueError("Environment exceeds demo limits (250 nodes, 2000 edges)")
    ids = set()
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
            raise ValueError("Each node needs a nonempty string id")
        if node["id"] in ids:
            raise ValueError("Duplicate node id: " + node["id"])
        if node.get("kind") not in VALID_KINDS:
            raise ValueError("Unknown resource kind: " + str(node.get("kind")))
        ids.add(node["id"])
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("source") not in ids or edge.get("target") not in ids:
            raise ValueError("Every edge must reference existing nodes")
        if edge.get("permission") not in {"reachable", "assume-role", "read", "write", "admin"}:
            raise ValueError("Unsupported edge permission")
    return environment


def analyze(environment):
    validate_environment(environment)
    nodes = {node["id"]: node for node in environment["nodes"]}
    adjacency = {node_id: [] for node_id in nodes}
    for index, edge in enumerate(environment["edges"]):
        if edge.get("enabled", True):
            adjacency[edge["source"]].append((edge["target"], index))
    findings = []
    sources = [node for node in nodes.values() if node["kind"] == "internet" or node.get("compromised", False)]
    for source in sources:
        queue = deque([(source["id"], [source["id"]], [])])
        while queue:
            current, path, edge_indices = queue.popleft()
            if len(path) > 6:
                continue
            for nxt, edge_idx in adjacency[current]:
                if nxt in path:
                    continue
                new_path = path + [nxt]
                new_indices = edge_indices + [edge_idx]
                target = nodes[nxt]
                if target["kind"] in SENSITIVE and target.get("sensitive", False):
                    # Illustrative score, not a CVSS rating or proof of exploitability.
                    impact = {"bucket": 65, "database": 80, "secret": 90}[target["kind"]]
                    score = min(100, impact + (15 if source["kind"] == "internet" else 5) - 4 * (len(new_path) - 2))
                    findings.append({
                        "id": f"{source['id']}:{nxt}:{'-'.join(map(str,new_indices))}",
                        "source": source["id"], "target": nxt, "path": new_path,
                        "edge_indices": new_indices, "score": score,
                        "severity": "critical" if score >= 90 else "high" if score >= 75 else "medium",
                        "reason": f"{'Public entry point' if source['kind'] == 'internet' else 'Assumed compromised principal'} can reach sensitive {target['kind']} via enabled modeled relationships.",
                        "limitations": "Reachability is inferred from simplified configuration relationships; this does not prove exploitation or account for every AWS policy condition."
                    })
                if len(new_path) < 6:
                    queue.append((nxt, new_path, new_indices))
    findings.sort(key=lambda f: (-f["score"], len(f["path"]), f["id"]))
    return {"findings": findings[:100], "total_paths": len(findings),
            "resources": len(nodes), "relationships": len(environment["edges"]),
            "critical": sum(f["severity"] == "critical" for f in findings),
            "high": sum(f["severity"] == "high" for f in findings),
            "note": "Synthetic graph-based exposure assessment; scores are illustrative, not CVSS."}


def simulate(environment, disabled_edges):
    validate_environment(environment)
    if not isinstance(disabled_edges, list) or any(type(i) is not int or i < 0 or i >= len(environment["edges"]) for i in disabled_edges):
        raise ValueError("disabled_edges must contain valid integer edge indices")
    changed = deepcopy(environment)
    for index in disabled_edges:
        changed["edges"][index]["enabled"] = False
    before, after = analyze(environment), analyze(changed)
    before_ids = {f["id"] for f in before["findings"]}
    after_ids = {f["id"] for f in after["findings"]}
    return {"before": before, "after": after, "removed_paths": len(before_ids - after_ids), "remaining_paths": after["total_paths"]}

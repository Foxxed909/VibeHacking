"""Offline AD privilege-path analysis from approved CSV exports."""
import csv
from collections import defaultdict, deque

RELATIONSHIPS = {"member_of", "generic_all", "write_dacl", "write_owner", "add_member"}
HIGH_RISK_EDGES = {"generic_all", "write_dacl", "write_owner", "add_member"}


def analyze_edges(csv_path, principal, critical=None, max_depth=10):
    if critical is None:
        critical = ["Domain Admins", "Enterprise Admins", "Administrators"]
    graph = defaultdict(list)
    edge_count = 0
    with open(csv_path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"source", "target", "relationship"}.issubset(reader.fieldnames):
            raise ValueError("CSV requires source,target,relationship columns")
        for row in reader:
            source = row["source"].strip()
            target = row["target"].strip()
            relation = row["relationship"].strip().lower()
            if relation not in RELATIONSHIPS:
                raise ValueError("Unsupported AD edge type: " + relation)
            if not source or not target:
                raise ValueError("Blank source or target in AD edge export")
            graph[source].append((target, relation))
            edge_count += 1

    queue = deque([(principal, [])])
    visited = {principal}
    discovered = []
    while queue:
        current, path = queue.popleft()
        if current in critical and path:
            is_risky = any(e["relationship"] in HIGH_RISK_EDGES for e in path)
            discovered.append({
                "critical_target": current,
                "path": path,
                "classification": "potential_acl_escalation" if is_risky else "privileged_membership",
            })
        if len(path) >= max_depth:
            continue
        for target, relation in graph.get(current, []):
            if target not in visited:
                visited.add(target)
                queue.append((target, path + [{
                    "source": current, "target": target, "relationship": relation
                }]))

    return {
        "principal": principal,
        "edges_analyzed": edge_count,
        "critical_targets": critical,
        "paths": discovered,
        "note": "An ACL path is a hypothesis to validate against AD object scope and inheritance.",
    }


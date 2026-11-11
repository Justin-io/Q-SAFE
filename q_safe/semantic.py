"""Mutation-tolerant structural features for Python source; never executes code."""
from __future__ import annotations
import ast, hashlib
from collections import Counter

DANGEROUS_CALLS = {
    "eval":18, "exec":18, "compile":10, "__import__":12,
    "system":9, "popen":9, "Popen":9, "run":7, "check_output":8,
    "connect":5, "urlopen":5, "CreateProcess":10, "VirtualAlloc":8,
    "WriteProcessMemory":12, "ptrace":12,
}
def dotted_name(node: ast.AST) -> str:
    parts=[]
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node=node.value
    if isinstance(node, ast.Name): parts.append(node.id)
    return ".".join(reversed(parts))

def python_features(source: bytes) -> dict:
    """Return a stable feature sketch, normalizing identifiers and literal values."""
    try:
        tree=ast.parse(source.decode("utf-8",errors="replace"))
    except (SyntaxError, ValueError, MemoryError):
        return {"parsed":False,"fingerprint":None,"node_counts":{},"imports":[],"calls":[],"risk_score":0,"indicators":[]}
    nodes=Counter(type(n).__name__ for n in ast.walk(tree))
    imports=set(); calls=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):
            imports.update(a.name for a in node.names)
        elif isinstance(node,ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node,ast.Call):
            name=dotted_name(node.func)
            if name: calls.add(name)
    # The fingerprint uses AST node-type counts and normalized imports/calls.
    # Local variable names and literal values are deliberately excluded.
    sketch="|".join([
        ",".join(f"{k}:{nodes[k]}" for k in sorted(nodes)),
        ",".join(sorted(imports)),
        ",".join(sorted(calls)),
    ])
    indicators=[]; score=0
    for call in sorted(calls):
        leaf=call.split(".")[-1]
        weight=DANGEROUS_CALLS.get(leaf,0)
        if weight:
            score+=weight; indicators.append(f"call:{call}")
    if (any(x in imports for x in ("socket","requests","urllib","http.client"))
        and any(x.split(".")[-1] in {"Popen","run","system","popen"} for x in calls)):
        score+=10; indicators.append("combination:process-launch-and-network")
    return {
        "parsed":True,
        "fingerprint":hashlib.sha256(sketch.encode()).hexdigest(),
        "node_counts":dict(nodes),
        "imports":sorted(imports),
        "calls":sorted(calls),
        "risk_score":min(score,50),
        "indicators":indicators,
    }

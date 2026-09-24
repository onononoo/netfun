"""scan comparison."""


def _key(h):
    return h["mac"] or h["ip"]


def compare(old, new):
    a = {_key(h): h for h in old["hosts"]}
    b = {_key(h): h for h in new["hosts"]}
    changes = {"new": [], "gone": [], "moved": [], "ports": []}
    for k in b.keys() - a.keys():
        changes["new"].append(b[k])
    for k in a.keys() - b.keys():
        changes["gone"].append(a[k])
    for k in a.keys() & b.keys():
        oh, nh = a[k], b[k]
        if oh["ip"] != nh["ip"]:
            changes["moved"].append((oh, nh))
        opened = sorted(set(nh["ports"]) - set(oh["ports"]))
        closed = sorted(set(oh["ports"]) - set(nh["ports"]))
        if opened or closed:
            changes["ports"].append((nh, opened, closed))
    return changes


def describe(h):
    name = h.get("label") or h.get("hostname") or h.get("device") or h.get("vendor") or ""
    return f"{h['ip']} {h['mac'] or '-'}{' ' + name if name else ''}"


def format_changes(changes):
    lines = []
    for h in changes["new"]:
        lines.append(f"new    {describe(h)}")
    for h in changes["gone"]:
        lines.append(f"gone   {describe(h)}")
    for oh, nh in changes["moved"]:
        lines.append(f"moved  {describe(nh)} from {oh['ip']}")
    for h, opened, closed in changes["ports"]:
        bits = [f"+{p}" for p in opened] + [f"-{p}" for p in closed]
        lines.append(f"ports  {describe(h)} {' '.join(bits)}")
    return lines or ["no changes"]


def is_empty(changes):
    return not any(changes.values())

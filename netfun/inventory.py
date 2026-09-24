"""every device ever seen."""

import json
import os

from .paths import HOME, ensure_home

INVENTORY_FILE = os.path.join(HOME, "devices.json")


def load():
    try:
        with open(INVENTORY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def update(result):
    ensure_home()
    inv = load()
    ts = result["timestamp"]
    for h in result["hosts"]:
        key = h["mac"] or h["ip"]
        d = inv.setdefault(key, {"first_seen": ts, "seen": 0, "ips": []})
        d["seen"] += 1
        d["last_seen"] = ts
        d["ip"] = h["ip"]
        if h["ip"] not in d["ips"]:
            d["ips"].append(h["ip"])
        for k in ("mac", "vendor", "hostname", "device"):
            if h.get(k):
                d[k] = h[k]
        if h.get("upnp", {}).get("friendly_name"):
            d["upnp_name"] = h["upnp"]["friendly_name"]
        d["ports"] = h["ports"]
    with open(INVENTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=2, sort_keys=True)
    return inv

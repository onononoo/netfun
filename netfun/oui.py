"""MAC address vendor lookup using the IEEE OUI registry."""

import csv
import functools
import os
import sys
import urllib.request

from .paths import OUI_CACHE, ensure_home

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def update():
    ensure_home()
    print(f"[*] Downloading {OUI_URL} ...", file=sys.stderr)
    req = urllib.request.Request(OUI_URL, headers={"User-Agent": "netfun/0.2"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    tmp = OUI_CACHE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, OUI_CACHE)
    load.cache_clear()
    print(f"[*] Saved {len(load())} vendor prefixes to {OUI_CACHE}", file=sys.stderr)


@functools.lru_cache(maxsize=1)
def load():
    """Return {'AABBCC': 'Vendor Name'} from the cached IEEE CSV, or {}."""
    if not os.path.exists(OUI_CACHE):
        return {}
    table = {}
    with open(OUI_CACHE, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            prefix = (row.get("Assignment") or "").strip().upper()
            if len(prefix) == 6:
                table[prefix] = (row.get("Organization Name") or "").strip()
    return table


def is_private_mac(mac):
    """True if the locally-administered bit is set (randomized/private MAC)."""
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)


def vendor(mac, table=None):
    if not mac:
        return ""
    if is_private_mac(mac):
        return "(private/random MAC)"
    table = load() if table is None else table
    return table.get(mac.replace(":", "").replace("-", "")[:6].upper(), "")

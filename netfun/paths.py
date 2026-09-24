"""data locations."""

import os

HOME = os.environ.get("NETFUN_HOME") or os.path.join(os.path.expanduser("~"), ".netfun")
OUI_CACHE = os.path.join(HOME, "oui.csv")
SCANS_DIR = os.path.join(HOME, "scans")
LABELS_FILE = os.path.join(HOME, "labels.json")


def ensure_home():
    os.makedirs(SCANS_DIR, exist_ok=True)

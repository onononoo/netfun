"""scan history and labels."""

import glob
import json
import os

from .paths import LABELS_FILE, SCANS_DIR, ensure_home


def save_scan(result):
    ensure_home()
    stamp = result["timestamp"].replace(":", "").replace("-", "")
    path = os.path.join(SCANS_DIR, f"scan-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return path


def list_scans():
    return sorted(glob.glob(os.path.join(SCANS_DIR, "scan-*.json")))


def load_scan(ref):
    # path, or history index (-1 = latest)
    if isinstance(ref, str) and os.path.exists(ref):
        path = ref
    else:
        scans = list_scans()
        try:
            path = scans[int(ref)]
        except (ValueError, IndexError):
            raise SystemExit(f"no scan: {ref}")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_labels():
    try:
        with open(LABELS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def set_label(key, name):
    ensure_home()
    labels = load_labels()
    key = key.lower().replace("-", ":")
    if name:
        labels[key] = name
    else:
        labels.pop(key, None)
    with open(LABELS_FILE, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2, sort_keys=True)
    return labels

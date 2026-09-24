"""Scan history and user-assigned device labels, stored under ~/.netfun."""

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
    """Load a scan by path, or by history index (-1 = latest, -2 = previous...)."""
    if isinstance(ref, str) and os.path.exists(ref):
        path = ref
    else:
        scans = list_scans()
        try:
            path = scans[int(ref)]
        except (ValueError, IndexError):
            raise SystemExit(f"No scan matching {ref!r} ({len(scans)} in history).")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_labels():
    try:
        with open(LABELS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def set_label(key, name):
    """Label a device by MAC (preferred; survives DHCP changes) or IP."""
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

"""device type guess."""

import re

VENDOR_HINTS = [
    (r"apple", "apple"),
    (r"samsung", "samsung"),
    (r"google|nest labs", "google/nest"),
    (r"amazon", "amazon"),
    (r"sonos", "speaker"),
    (r"roku", "roku"),
    (r"espressif|tuya|shelly|wiz |lifx|signify|philips lighting|lumi united", "iot"),
    (r"raspberry", "raspberry pi"),
    (r"hewlett|hp inc|brother|canon|epson|xerox|lexmark|kyocera", "printer"),
    (r"synology|qnap|western digital", "nas"),
    (r"netgear|tp-link|asustek|ubiquiti|cisco|linksys|arris|eero|mikrotik|d-link|"
     r"sercomm|technicolor|zyxel", "network"),
    (r"intel|realtek|dell|lenovo|micro-star|gigabyte|asrock|liteon|azurewave", "pc"),
    (r"nintendo", "console"),
    (r"sony interactive", "console"),
    (r"microsoft", "microsoft"),
    (r"lg electronics|vizio|tcl|hisense", "tv"),
    (r"chamberlain", "garage opener"),
    (r"ecobee", "thermostat"),
    (r"logitech", "logitech"),
    (r"ring llc|wyze|arlo|hikvision|dahua|reolink", "camera"),
]


def classify(host):
    ports = set(host.get("ports", []))
    vendor = (host.get("vendor") or "").lower()
    banners = " ".join(host.get("services", {}).values()).lower()

    if host.get("gateway"):
        return "router"
    if 9100 in ports or 631 in ports or "printer" in banners:
        return "printer"
    if 62078 in ports:
        return "iphone/ipad"
    if 8009 in ports:
        if re.search(r"vizio|lg electronics|tcl|hisense|sony|philips|sharp", vendor):
            return "tv"
        return "chromecast"
    if 32400 in ports:
        return "plex"
    if 3389 in ports or {135, 445} <= ports:
        return "windows"
    if 554 in ports:
        return "camera"
    if 1883 in ports:
        return "mqtt"
    for pat, label in VENDOR_HINTS:
        if re.search(pat, vendor):
            return label
    if 22 in ports:
        return "linux"
    if vendor == "private mac":
        return "phone/laptop"
    return ""

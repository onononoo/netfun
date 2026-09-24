"""Best-effort guess at what kind of device a host is."""

import re

VENDOR_HINTS = [
    (r"apple", "Apple device"),
    (r"samsung", "Samsung device"),
    (r"google|nest labs", "Google/Nest device"),
    (r"amazon", "Amazon device (Echo/Fire/Ring)"),
    (r"sonos", "Sonos speaker"),
    (r"roku", "Roku streamer"),
    (r"espressif|tuya|shelly|wiz |lifx|signify|philips lighting|lumi united", "IoT / smart home"),
    (r"raspberry", "Raspberry Pi"),
    (r"hewlett|hp inc|brother|canon|epson|xerox|lexmark|kyocera", "Printer"),
    (r"synology|qnap|western digital", "NAS"),
    (r"netgear|tp-link|asustek|ubiquiti|cisco|linksys|arris|eero|mikrotik|d-link|"
     r"sercomm|technicolor|zyxel", "Network gear"),
    (r"intel|realtek|dell|lenovo|micro-star|gigabyte|asrock|liteon|azurewave", "PC / laptop"),
    (r"nintendo", "Nintendo console"),
    (r"sony interactive", "PlayStation"),
    (r"microsoft", "Microsoft device (Xbox/Surface)"),
    (r"lg electronics|vizio|tcl|hisense", "Smart TV"),
    (r"chamberlain", "Garage door opener"),
    (r"ecobee", "Thermostat"),
    (r"logitech", "Logitech device (Harmony hub)"),
    (r"ring llc|wyze|arlo|hikvision|dahua|reolink", "Camera"),
]


def classify(host):
    ports = set(host.get("ports", []))
    vendor = (host.get("vendor") or "").lower()
    banners = " ".join(host.get("services", {}).values()).lower()

    if host.get("gateway"):
        return "Router / gateway"
    if 9100 in ports or 631 in ports or "printer" in banners:
        return "Printer"
    if 62078 in ports:
        return "iPhone / iPad"
    if 8009 in ports:
        if re.search(r"vizio|lg electronics|tcl|hisense|sony|philips|sharp", vendor):
            return "Smart TV (Chromecast built-in)"
        return "Chromecast / Google speaker"
    if 32400 in ports:
        return "Plex server"
    if 3389 in ports or {135, 445} <= ports:
        return "Windows PC"
    if 554 in ports:
        return "Camera / NVR"
    if 1883 in ports:
        return "MQTT / home automation"
    for pat, label in VENDOR_HINTS:
        if re.search(pat, vendor):
            return label
    if 22 in ports:
        return "Linux / server"
    if vendor == "(private/random mac)":
        return "Phone / laptop (private MAC)"
    return ""

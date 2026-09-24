"""upnp/ssdp discovery."""

import concurrent.futures as cf
import re
import socket
import time
import urllib.request
import xml.etree.ElementTree as ET

GROUP = ("239.255.255.250", 1900)
SEARCH = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
          "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()


def parse_response(text):
    headers = {}
    for line in text.split("\r\n")[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    return headers


def search(timeout=3.0, src_ip=""):
    # ip -> {location, server}
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if src_ip:
            s.bind((src_ip, 0))
        s.settimeout(0.5)
        try:
            s.sendto(SEARCH, GROUP)
            s.sendto(SEARCH, GROUP)
        except OSError:
            return {}
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            h = parse_response(data.decode("utf-8", "replace"))
            entry = found.setdefault(ip, {"location": "", "server": ""})
            if h.get("location") and not entry["location"]:
                entry["location"] = h["location"]
            if h.get("server") and not entry["server"]:
                entry["server"] = h["server"]
    return found


def parse_description(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    out = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType"):
        el = root.find(f".//{{*}}device/{{*}}{tag}")
        if el is not None and el.text:
            out[re.sub(r"(?<!^)([A-Z])", r"_\1", tag).lower()] = el.text.strip()
    return out


def describe(location, timeout=2.0):
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "netfun"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return parse_description(r.read(65536).decode("utf-8", "replace"))
    except Exception:
        return {}


def discover(timeout=3.0, src_ip=""):
    # ip -> {friendly_name, manufacturer, model_name, ..., server}
    found = search(timeout, src_ip)
    with cf.ThreadPoolExecutor(16) as ex:
        futs = {ex.submit(describe, v["location"]): ip for ip, v in found.items() if v["location"]}
        for f in cf.as_completed(futs):
            desc = f.result()
            # wps descriptors carry generic names
            if "wifialliance" in desc.get("device_type", ""):
                continue
            found[futs[f]].update(desc)
    return found

"""Wake-on-LAN magic packets."""

import re
import socket


def magic_packet(mac):
    hexmac = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexmac) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")
    return b"\xff" * 6 + bytes.fromhex(hexmac) * 16


def wake(mac, broadcast="255.255.255.255", port=9):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic_packet(mac), (broadcast, port))

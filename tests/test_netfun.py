import struct
import unittest

from netfun import classify, diff, discovery, oui, ports, ssdp, wol


class TestPorts(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(ports.parse_ports("22, 80,8000-8002,80"), [22, 80, 8000, 8001, 8002])
        self.assertEqual(ports.parse_ports("0,70000,5"), [5])

    def test_http_banner(self):
        text = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><title> My  Router </title>"
        self.assertEqual(ports.summarize_banner(text), "nginx | My Router")

    def test_plain_banner(self):
        self.assertEqual(ports.summarize_banner("SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6")


class TestDiscovery(unittest.TestCase):
    def test_parse_arp_windows(self):
        text = ("  192.168.1.1          f0-2f-74-2b-25-b0     dynamic\n"
                "  192.168.1.255        ff-ff-ff-ff-ff-ff     static\n"
                "  224.0.0.22           01-00-5e-00-00-16     static\n")
        self.assertEqual(discovery.parse_arp(text), {"192.168.1.1": "f0:2f:74:2b:25:b0"})

    def test_parse_arp_mac_style(self):
        text = "? (10.0.0.5) at 0:3:7f:c3:ee:9a on en0 ifscope [ethernet]"
        self.assertEqual(discovery.parse_arp(text), {"10.0.0.5": "00:03:7f:c3:ee:9a"})

    def test_os_from_ttl(self):
        self.assertEqual(discovery.os_from_ttl(64), "unix-like")
        self.assertEqual(discovery.os_from_ttl(128), "windows")
        self.assertEqual(discovery.os_from_ttl(255), "network")
        self.assertEqual(discovery.os_from_ttl(None), "")

    def test_parse_ptr_answer(self):
        name = b"\x07printer\x05local\x00"
        q = b"\x015\x011\x03168\x03192\x07in-addr\x04arpa\x00"
        pkt = (struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0) + q + struct.pack(">HH", 12, 1)
               + b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(name)) + name)
        self.assertEqual(discovery._parse_ptr_answer(pkt), "printer.local")


class TestOui(unittest.TestCase):
    def test_vendor(self):
        table = {"F02F74": "Acme Corp"}
        self.assertEqual(oui.vendor("f0:2f:74:2b:25:b0", table), "Acme Corp")
        self.assertEqual(oui.vendor("f2:2f:74:2b:25:b0", table), "private mac")
        self.assertEqual(oui.vendor("", table), "")


class TestClassify(unittest.TestCase):
    def test_rules(self):
        base = {"vendor": "", "services": {}}
        self.assertEqual(classify.classify({**base, "gateway": True, "ports": []}), "router")
        self.assertEqual(classify.classify({**base, "ports": [9100]}), "printer")
        self.assertEqual(classify.classify({**base, "ports": [62078]}), "iphone/ipad")
        self.assertEqual(classify.classify({**base, "ports": [], "vendor": "Raspberry Pi Trading"}),
                         "raspberry pi")


class TestDiff(unittest.TestCase):
    def host(self, ip, mac, p=()):
        return {"ip": ip, "mac": mac, "ports": list(p)}

    def test_compare(self):
        old = {"hosts": [self.host("1.1.1.1", "aa", [80]), self.host("1.1.1.2", "bb"),
                         self.host("1.1.1.3", "cc")]}
        new = {"hosts": [self.host("1.1.1.1", "aa", [80, 22]), self.host("1.1.1.9", "bb"),
                         self.host("1.1.1.4", "dd")]}
        c = diff.compare(old, new)
        self.assertEqual([h["mac"] for h in c["new"]], ["dd"])
        self.assertEqual([h["mac"] for h in c["gone"]], ["cc"])
        self.assertEqual(c["moved"][0][1]["ip"], "1.1.1.9")
        self.assertEqual(c["ports"][0][1:], ([22], []))


class TestSsdp(unittest.TestCase):
    def test_parse_response(self):
        h = ssdp.parse_response("HTTP/1.1 200 OK\r\nLOCATION: http://1.2.3.4:80/d.xml\r\nSERVER: x\r\n\r\n")
        self.assertEqual(h["location"], "http://1.2.3.4:80/d.xml")

    def test_parse_description(self):
        xml = ('<root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
               '<friendlyName>Family Room TV</friendlyName><manufacturer>Sony</manufacturer>'
               '<modelName>BRAVIA</modelName></device></root>')
        d = ssdp.parse_description(xml)
        self.assertEqual(d, {"friendly_name": "Family Room TV", "manufacturer": "Sony",
                             "model_name": "BRAVIA"})

    def test_classify_tv(self):
        h = {"ports": [8009], "vendor": "WNC Corporation", "services": {},
             "upnp": {"model_name": "BRAVIA VH1"}}
        self.assertEqual(classify.classify(h), "tv")


class TestWol(unittest.TestCase):
    def test_magic_packet(self):
        pkt = wol.magic_packet("aa-bb-cc-dd-ee-ff")
        self.assertEqual(len(pkt), 102)
        self.assertTrue(pkt.startswith(b"\xff" * 6 + bytes.fromhex("aabbccddeeff")))
        with self.assertRaises(ValueError):
            wol.magic_packet("nope")


if __name__ == "__main__":
    unittest.main()

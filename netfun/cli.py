"""Command-line interface: `netfun <command>`."""

import argparse
import datetime
import ipaddress
import sys
import time

from . import __version__, diff, discovery, oui, report, store, wol
from .ports import COMMON_PORTS, parse_ports, port_open, service_name
from .scanner import scan

MAX_ADDRESSES = 4096


def _network(arg):
    net = ipaddress.ip_network(arg, strict=False) if arg else discovery.default_subnet()
    if net.num_addresses > MAX_ADDRESSES:
        sys.exit(f"{net} is large ({net.num_addresses} addresses); use a /20 or smaller.")
    return net


def _add_scan_opts(p):
    p.add_argument("network", nargs="?", help="CIDR to scan (default: your /24)")
    p.add_argument("-p", "--ports", help="ports, e.g. 22,80,8000-8100 (default: common ports)")
    p.add_argument("-w", "--workers", type=int, default=128)
    p.add_argument("--ping-timeout", type=int, default=800, help="ms")
    p.add_argument("--port-timeout", type=float, default=0.5, help="seconds")
    p.add_argument("--no-banners", action="store_true", help="skip service banner grabbing")


def _do_scan(args, quiet=False):
    return scan(_network(args.network),
                ports=parse_ports(args.ports) if args.ports else COMMON_PORTS,
                workers=args.workers, ping_timeout=args.ping_timeout,
                port_timeout=args.port_timeout, banners=not args.no_banners, quiet=quiet)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_scan(args):
    result = _do_scan(args)
    report.print_table(result)
    if not args.no_save:
        prev = store.list_scans()
        path = store.save_scan(result)
        print(f"\nSaved to {path}")
        if prev:
            old = store.load_scan(prev[-1])
            if old["network"] == result["network"]:
                print(f"\nChanges since {old['timestamp']}:")
                for line in diff.format_changes(diff.compare(old, result)):
                    print("  " + line)
    if args.json:
        report.write_json(result, args.json)
        print(f"Wrote {args.json}")
    if args.csv:
        report.write_csv(result, args.csv)
        print(f"Wrote {args.csv}")
    if args.html:
        report.write_html(result, args.html)
        print(f"Wrote {args.html}")


def cmd_report(args):
    result = store.load_scan(args.scan)
    out = args.output or f"netfun-report.{args.format}"
    {"html": report.write_html, "csv": report.write_csv, "json": report.write_json}[args.format](result, out)
    print(f"Wrote {out} from scan at {result['timestamp']}")


def cmd_show(args):
    report.print_table(store.load_scan(args.scan), show_ports=not args.brief)


def cmd_diff(args):
    old, new = store.load_scan(args.old), store.load_scan(args.new)
    print(f"{old['timestamp']}  ->  {new['timestamp']}")
    for line in diff.format_changes(diff.compare(old, new)):
        print("  " + line)


def cmd_history(args):
    scans = store.list_scans()
    if not scans:
        print("No scans yet. Run `netfun scan`.")
        return
    n = len(scans)
    for i, path in enumerate(scans[-args.limit:], start=max(0, n - args.limit)):
        s = store.load_scan(path)
        print(f"{i - n:>4}  {s['timestamp']}  {s['network']:<18} {len(s['hosts']):>3} hosts")
    print("\nUse the index (e.g. -1 for latest) with show/diff/report.")


def cmd_watch(args):
    print(f"Watching every {args.interval}s. Ctrl+C to stop.", file=sys.stderr)
    last = None
    scans = store.list_scans()
    if scans:
        last = store.load_scan(scans[-1])
    try:
        while True:
            result = _do_scan(args, quiet=True)
            now = datetime.datetime.now().strftime("%H:%M:%S")
            if last and last["network"] == result["network"]:
                changes = diff.compare(last, result)
                if not diff.is_empty(changes):
                    for line in diff.format_changes(changes):
                        print(f"[{now}] {line}", flush=True)
                    if args.beep:
                        print("\a", end="", flush=True)
                else:
                    print(f"[{now}] no changes ({len(result['hosts'])} hosts)", flush=True)
            else:
                print(f"[{now}] baseline: {len(result['hosts'])} hosts", flush=True)
            store.save_scan(result)
            last = result
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass


def cmd_ports(args):
    """Deep port scan of a single host."""
    import concurrent.futures as cf
    from .ports import grab_banner

    ports = parse_ports(args.ports)
    print(f"Scanning {len(ports)} ports on {args.host}...", file=sys.stderr)
    with cf.ThreadPoolExecutor(args.workers) as ex:
        opened = [p for p, ok in zip(ports, ex.map(lambda p: port_open(args.host, p, args.timeout), ports)) if ok]
        banners = dict(zip(opened, ex.map(lambda p: grab_banner(args.host, p), opened)))
    for p in opened:
        print(f"{p:>5}/tcp  {service_name(p):<14} {banners[p]}")
    print(f"\n{len(opened)} open of {len(ports)} scanned.")


def cmd_label(args):
    if args.key is None:
        labels = store.load_labels()
        for k, v in sorted(labels.items()):
            print(f"{k:<20} {v}")
        if not labels:
            print("No labels. Example: netfun label aa:bb:cc:dd:ee:ff \"Living room TV\"")
        return
    store.set_label(args.key, args.name)
    print(f"{'Labeled' if args.name else 'Removed label for'} {args.key}")


def cmd_vendor(args):
    for mac in args.mac:
        print(f"{mac:<20} {oui.vendor(discovery.normalize_mac(mac)) or 'unknown'}")


def cmd_wake(args):
    mac = args.target
    if ":" not in mac and "-" not in mac:
        labels = {v.lower(): k for k, v in store.load_labels().items()}
        mac = labels.get(mac.lower(), mac)
    wol.wake(mac, args.broadcast)
    print(f"Sent Wake-on-LAN packet to {mac}")


def cmd_info(args):
    print(f"netfun {__version__}")
    print(f"Local IP:     {discovery.local_ip()}")
    print(f"Gateway:      {discovery.default_gateway() or 'unknown'}")
    print(f"Subnet:       {discovery.default_subnet()}")
    print(f"Vendor DB:    {len(oui.load())} prefixes")
    print(f"Saved scans:  {len(store.list_scans())}")
    print(f"Labels:       {len(store.load_labels())}")


# --------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(prog="netfun", description="Map and watch your local network.")
    ap.add_argument("--version", action="version", version=f"netfun {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan the network and save the result")
    _add_scan_opts(p)
    p.add_argument("--json", metavar="FILE")
    p.add_argument("--csv", metavar="FILE")
    p.add_argument("--html", metavar="FILE", help="write an HTML report with a network map")
    p.add_argument("--no-save", action="store_true", help="don't add to scan history")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("watch", help="rescan on an interval and report changes")
    _add_scan_opts(p)
    p.add_argument("-i", "--interval", type=int, default=300, help="seconds between scans")
    p.add_argument("--beep", action="store_true", help="beep when something changes")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("show", help="print a saved scan")
    p.add_argument("scan", nargs="?", default="-1", help="history index or file (default: latest)")
    p.add_argument("--brief", action="store_true", help="hide port details")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("history", help="list saved scans")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("diff", help="compare two saved scans")
    p.add_argument("old", nargs="?", default="-2")
    p.add_argument("new", nargs="?", default="-1")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("report", help="export a saved scan as HTML/CSV/JSON")
    p.add_argument("scan", nargs="?", default="-1")
    p.add_argument("-f", "--format", choices=["html", "csv", "json"], default="html")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("ports", help="deep port scan of one host")
    p.add_argument("host")
    p.add_argument("-p", "--ports", default="1-1024")
    p.add_argument("-w", "--workers", type=int, default=256)
    p.add_argument("-t", "--timeout", type=float, default=0.5)
    p.set_defaults(func=cmd_ports)

    p = sub.add_parser("label", help="name a device (by MAC or IP); no args lists labels")
    p.add_argument("key", nargs="?")
    p.add_argument("name", nargs="?", default="", help="omit to remove the label")
    p.set_defaults(func=cmd_label)

    p = sub.add_parser("vendor", help="look up the vendor of MAC addresses")
    p.add_argument("mac", nargs="+")
    p.set_defaults(func=cmd_vendor)

    p = sub.add_parser("wake", help="send a Wake-on-LAN packet (MAC or label)")
    p.add_argument("target")
    p.add_argument("--broadcast", default="255.255.255.255")
    p.set_defaults(func=cmd_wake)

    p = sub.add_parser("update-oui", help="download the IEEE MAC vendor database")
    p.set_defaults(func=lambda a: oui.update())

    p = sub.add_parser("info", help="show local network info and netfun status")
    p.set_defaults(func=cmd_info)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

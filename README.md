# netfun

A dependency-free Python toolkit for mapping and watching your local network.
Finds every device, names it, identifies its maker, checks common ports, and tells you
when something new shows up.

> Only scan networks you own or are authorized to test.

## Install

```bash
pip install -e .
netfun update-oui     # one-time: download the IEEE MAC vendor list (~5 MB)
```

Or run without installing: `python -m netfun <command>`. Requires Python 3.9+.

## Commands

| Command | What it does |
| --- | --- |
| `netfun scan [CIDR]` | Scan the network (default: your /24), save to history, show changes since last scan |
| `netfun scan --html map.html` | Also write an HTML report with a network map and filterable table (`--csv`, `--json` too) |
| `netfun watch -i 300` | Rescan every 5 minutes and print new/gone/moved devices and port changes |
| `netfun show [N]` | Print a saved scan (`-1` = latest) |
| `netfun history` | List saved scans |
| `netfun diff [OLD] [NEW]` | Compare two saved scans (default: previous vs latest) |
| `netfun report [N] -f html` | Export a saved scan as HTML, CSV or JSON |
| `netfun ports HOST -p 1-65535` | Deep port scan of one host with banners |
| `netfun label MAC "Name"` | Give a device a friendly name (shown in scans; omit name to remove) |
| `netfun vendor MAC...` | Look up who made a MAC address |
| `netfun wake MAC-or-label` | Send a Wake-on-LAN packet |
| `netfun info` | Local IP, gateway, subnet, and netfun status |

## How a scan works

1. **Ping sweep** of every address, keeping each reply's TTL (a rough OS hint) and round-trip time.
2. **ARP table** read, which catches devices that ignore ping.
3. **Names** via reverse DNS, then unicast mDNS (`.local`), then NetBIOS.
4. **MAC vendor** from the IEEE registry; randomized "private" MACs are flagged.
5. **TCP ports** from a list of ~30 common services, then **banners** (HTTP server/title, SSH version, etc.).
6. **Device guess** from ports, vendor and banners, plus **warnings** for risky services (Telnet, FTP, RDP, VNC, exposed databases...).

## Data

Everything lives in `~/.netfun` (override with `NETFUN_HOME`):
`oui.csv` (vendor DB), `scans/` (history as JSON), `labels.json`.

## Tests

```bash
python -m unittest discover tests
```

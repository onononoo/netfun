"""local web view."""

import html
import http.server
import json
import threading
import time

from . import inventory, report, store

_state = {"latest": None, "lock": threading.Lock()}


def _latest():
    with _state["lock"]:
        if _state["latest"] is None and store.list_scans():
            _state["latest"] = store.load_scan("-1")
        return _state["latest"]


def _devices_html():
    rows = []
    inv = sorted(inventory.load().items(), key=lambda kv: kv[1].get("last_seen", ""), reverse=True)
    for key, d in inv:
        name = d.get("upnp_name") or d.get("hostname") or "-"
        rows.append(f"<tr><td>{html.escape(d.get('ip', ''))}</td><td>{html.escape(key)}</td>"
                    f"<td>{html.escape(d.get('vendor', ''))}</td><td>{html.escape(name)}</td>"
                    f"<td>{html.escape(d.get('device', ''))}</td><td>{d.get('first_seen', '')}</td>"
                    f"<td>{d.get('last_seen', '')}</td><td>{d.get('seen', 0)}</td></tr>")
    return (f"<!doctype html><meta charset=utf-8><title>netfun devices</title>"
            f"<style>{report._CSS}</style><main><h1>devices</h1>"
            f"<div class=meta><a href=/>latest</a></div><div class=tw><table><thead><tr>"
            f"<th>ip</th><th>mac</th><th>vendor</th><th>name</th><th>type</th><th>first</th>"
            f"<th>last</th><th>seen</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></main>")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        latest = _latest()
        if path == "/":
            if not latest:
                return self._send("no scans. run: netfun scan")
            page = report.render_html(latest).replace(
                '<h1>netfun</h1>', '<h1>netfun</h1><div class="meta"><a href="/devices">devices</a></div>')
            return self._send(page)
        if path == "/devices":
            return self._send(_devices_html())
        if path == "/api/latest":
            return self._send(json.dumps(latest), "application/json")
        if path == "/api/devices":
            return self._send(json.dumps(inventory.load()), "application/json")
        if path == "/api/history":
            items = [{"index": i - len(s), "file": p} for s in [store.list_scans()] for i, p in enumerate(s)]
            return self._send(json.dumps(items), "application/json")
        self._send("not found", "text/plain", 404)


def run(host, port, rescan=None, interval=0):
    if rescan and interval:
        def loop():
            while True:
                result = rescan()
                store.save_scan(result)
                inventory.update(result)
                with _state["lock"]:
                    _state["latest"] = result
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()
    srv = http.server.ThreadingHTTPServer((host, port), Handler)
    print(f"http://{host}:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

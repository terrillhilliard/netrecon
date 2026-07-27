"""``netrecon serve`` — local web console.

Serves the RECON CONSOLE dashboard **and** a bettercap-compatible REST API
backed by the netrecon engine, so the same UI runs on your own tooling. A
background thread rescans the LAN on an interval; an optional monitor thread
(Administrator) adds live traffic counters and DNS events.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional

from . import discovery, enrich, net, output, scanner, store

WEB_DIR = Path(__file__).parent / "web"


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).astimezone().isoformat()


def _self_mac() -> str:
    n = uuid.getnode()
    return ":".join(f"{(n >> b) & 0xFF:02x}" for b in range(40, -1, -8))


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.hosts: List[dict] = []
        self.gateway = {"ipv4": "", "mac": ""}
        self.interface = {
            "ipv4": net.local_ipv4(),
            "mac": _self_mac(),
            "hostname": socket.gethostname(),
        }
        self.traffic: Dict[str, dict] = {}
        self.protos: Dict[str, int] = {}
        self.stats = {"sent": 0, "received": 0, "pkts_received": 0}
        self.events: List[dict] = []
        self.started_at = time.time()
        self.mitm = None  # active MitmSession, if any
        self.ai_key = None
        self.ai_model = None
        self.db_path = None
        self.vt_key = None
        self.ha_key = None
        self.nvd_key = None

    def session(self) -> dict:
        with self.lock:
            return {
                "interface": self.interface,
                "gateway": self.gateway,
                "lan": {"hosts": self.hosts},
                "wifi": {"aps": []},
                "ble": {"devices": []},
                "packets": {"stats": dict(self.stats), "protos": dict(self.protos),
                            "traffic": dict(self.traffic)},
                "started_at": _iso(self.started_at),
            }

    def add_event(self, tag: str, data: dict) -> None:
        with self.lock:
            self.events.append({"tag": tag, "time": _iso(time.time()), "data": data})
            self.events = self.events[-100:]


def scan_once(state: State, target: str, ports, timeout: float, db_path: str,
              store_it: bool = True) -> None:
    targets = net.expand_targets(target)
    live = set(discovery.discover(targets))
    arp = discovery.arp_table()
    tset = set(targets)
    live.update(ip for ip in arp if ip in tset)
    live_sorted = net.sort_ips(live)
    scan_res = scanner.scan(live_sorted, ports, timeout=timeout)

    now = time.time()
    known = {h["ipv4"] for h in state.hosts}
    hosts = []
    for ip in live_sorted:
        mac = arp.get(ip, "")
        ports_map = {
            str(p): {"port": p, "proto": "tcp", "service": enrich.service_name(p),
                     "banner": enrich.banner(ip, p)}
            for p in scan_res.get(ip, [])
        }
        host = {
            "ipv4": ip, "ipv6": "", "mac": mac, "alias": "",
            "hostname": enrich.hostname(ip),
            "vendor": enrich.vendor(mac) if mac else "",
            "first_seen": _iso(now), "last_seen": _iso(now),
            "meta": {"values": {"ports": ports_map} if ports_map else {}},
        }
        hosts.append(host)
        if ip not in known:
            state.add_event("endpoint.new", {"ipv4": ip, "hostname": host["hostname"], "mac": mac})

    gw_ip = ""
    if "/" in target:
        netobj = ipaddress.ip_network(target, strict=False)
        if netobj.num_addresses > 2:
            gw_ip = str(next(netobj.hosts()))
    with state.lock:
        state.hosts = hosts
        if gw_ip:
            state.gateway = {"ipv4": gw_ip, "mac": arp.get(gw_ip, "")}

    if store_it:
        con = store.connect(db_path)
        store.save_scan(con, target, [
            {"ip": h["ipv4"], "mac": h["mac"], "hostname": h["hostname"], "vendor": h["vendor"],
             "ports": [{"port": v["port"], "service": v["service"], "banner": ""}
                       for v in h["meta"]["values"].get("ports", {}).values()]}
            for h in hosts
        ])
        con.close()


def _scanner_loop(state, target, ports, timeout, db_path, interval, stop):
    while not stop.is_set():
        try:
            scan_once(state, target, ports, timeout, db_path)
        except Exception as e:  # keep the server alive
            state.add_event("sys.log", {"message": f"scan error: {e}"})
        stop.wait(interval)


def _monitor_loop(state, iface_ip, stop):
    from . import monitor

    def on_pkt(proto, src, dst, sport, dport, length):
        with state.lock:
            state.stats["pkts_received"] += 1
            pn = monitor.proto_name(proto).upper()
            state.protos[pn] = state.protos.get(pn, 0) + 1
            local = state.interface["ipv4"]
            if src == local:
                state.stats["sent"] += length
                state.traffic.setdefault(dst, {"sent": 0, "received": 0})["sent"] += length
            elif dst == local:
                state.stats["received"] += length
                state.traffic.setdefault(src, {"sent": 0, "received": 0})["received"] += length

    def on_dns(client, server, qname):
        state.add_event("dns", {"ipv4": client, "hostname": qname})

    try:
        monitor.capture(on_pkt, on_dns, iface_ip=iface_ip, should_stop=stop.is_set)
    except Exception as e:
        state.add_event("sys.log", {"message": f"monitor unavailable ({e}) - run as Administrator"})


def start_mitm(state: State, target: str) -> dict:
    """Launch an ARP-spoof MITM against `target`, feeding capture into state."""
    if not target:
        return {"success": False, "error": "no target specified"}
    if state.mitm is not None:
        return {"success": False, "error": "MITM already running - stop it first"}
    gw = state.gateway.get("ipv4")
    if not gw:
        return {"success": False, "error": "gateway unknown (rescan first)"}

    from . import mitm as mitm_mod

    def on_flow(src, dst, proto, dport, length):
        with state.lock:
            state.stats["pkts_received"] += 1
            pn = (proto or "").upper()
            state.protos[pn] = state.protos.get(pn, 0) + 1
            peer = dst if src == target else src
            t = state.traffic.setdefault(peer, {"sent": 0, "received": 0})
            if src == target:
                t["sent"] += length
            else:
                t["received"] += length

    def on_dns(client, qname):
        state.add_event("dns", {"ipv4": client, "hostname": qname})

    def on_http(client, host):
        state.add_event("http", {"ipv4": client, "hostname": host})

    try:
        sess = mitm_mod.MitmSession(target, gw, iface_ip=state.interface.get("ipv4"),
                                    on_flow=on_flow, on_dns=on_dns, on_http=on_http)
        sess.start()
    except ImportError:
        return {"success": False, "error": "scapy not installed (pip install scapy)"}
    except (PermissionError, OSError) as e:
        return {"success": False, "error": f"needs Administrator + Npcap: {e}"}
    except RuntimeError as e:
        return {"success": False, "error": str(e)}

    state.mitm = sess
    state.add_event("sys.log", {"message": f"MITM started on {target}"})
    return {"success": True, "note": f"MITM {target} started - see the TRAFFIC view"}


def stop_mitm(state: State) -> dict:
    if state.mitm is not None:
        try:
            state.mitm.stop()
        except Exception:
            pass
        state.mitm = None
        state.add_event("sys.log", {"message": "MITM stopped, ARP restored"})
    return {"success": True}


class Handler(BaseHTTPRequestHandler):
    state: Optional[State] = None

    def log_message(self, *args):  # silence default logging
        pass

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode())

    def do_OPTIONS(self):
        self._send(204)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            f = WEB_DIR / "index.html"
            if f.exists():
                self._send(200, f.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(404, b"dashboard not bundled")
            return
        if path == "/api/session":
            self._json(self.state.session())
            return
        if path == "/api/session/lan":
            self._json({"hosts": self.state.session()["lan"]["hosts"]})
            return
        if path.startswith("/api/session/lan/"):
            mac = path.rsplit("/", 1)[-1].lower()
            for h in self.state.hosts:
                if (h.get("mac") or "").lower() == mac:
                    self._json(h)
                    return
            self._json({}, 404)
            return
        if path == "/api/events":
            with self.state.lock:
                self._json(list(self.state.events))
            return
        if path == "/api/alerts":
            try:
                con = store.connect(self.state.db_path or store.DEFAULT_DB)
                rows = [dict(r) for r in store.recent_alerts(con, limit=100)]
                con.close()
                self._json(rows)
            except Exception as e:
                self._json({"error": str(e)}, 500)
            return
        if path.startswith("/api/session/"):
            key = path.rsplit("/", 1)[-1]
            self._json(self.state.session().get(key, {}))
            return
        self._send(404, b"not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/api/mitm":
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                data = {}
            self._json(start_mitm(self.state, data.get("target")))
            return
        if path == "/api/mitm/stop":
            self._json(stop_mitm(self.state))
            return
        if path == "/api/intel":
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                data = {}
            indicator = (data.get("indicator") or "").strip()
            if not indicator:
                self._json({"error": "empty indicator"}, 400)
                return
            from . import intel
            try:
                self._json(intel.lookup(indicator, vt_key=self.state.vt_key, ha_key=self.state.ha_key))
            except Exception as e:
                self._json({"error": f"intel lookup failed: {e}"}, 502)
            return
        if path == "/api/ask":
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                data = {}
            question = (data.get("question") or "").strip()
            if not question:
                self._json({"error": "empty question"}, 400)
                return
            from . import ai, nvd
            try:
                with self.state.lock:
                    events = list(self.state.events)
                sess = self.state.session()
                ctx = ai.build_context(sess, events)
                cve = nvd.context_block((sess.get("lan", {}) or {}).get("hosts", []), key=self.state.nvd_key)
                if cve:
                    ctx += "\n\nLIVE NVD CVE DATA (current, from services.nvd.nist.gov) — use these real CVEs:\n" + cve
                answer = ai.ask(question, ctx, model=self.state.ai_model, key=self.state.ai_key)
                self._json({"answer": answer})
            except RuntimeError as e:
                self._json({"error": str(e)}, 400)
            except Exception as e:
                self._json({"error": f"AI request failed: {e}"}, 502)
            return
        # other command posts: netrecon serve is read-only.
        self._json({"success": True, "note": "netrecon serve is read-only - use the CLI"})


def make_handler(state: State):
    return type("BoundHandler", (Handler,), {"state": state})


def serve(host="127.0.0.1", port=8081, target=None, ports=None, timeout=0.6,
          db_path=None, rescan=60, monitor_on=False, open_browser=True, iface=None,
          ai_key=None, ai_model=None, vt_key=None, ha_key=None, nvd_key=None) -> None:
    state = State()
    state.ai_key = ai_key
    state.ai_model = ai_model
    state.db_path = db_path or store.DEFAULT_DB
    state.vt_key = vt_key
    state.ha_key = ha_key
    state.nvd_key = nvd_key
    if iface and iface.get("ipv4"):
        state.interface = {"ipv4": iface["ipv4"], "mac": iface.get("mac") or _self_mac(),
                           "hostname": socket.gethostname()}
        output.note(f"interface [bold]{iface.get('name', '?')}[/] ({iface['ipv4']})")
    target = target or net.subnet_for(state.interface["ipv4"])
    ports = ports or scanner.TOP_PORTS
    db_path = db_path or store.DEFAULT_DB
    stop = threading.Event()

    output.note(f"initial scan of [bold]{target}[/] ...")
    scan_once(state, target, ports, timeout, db_path)
    output.note(f"[green]{len(state.hosts)}[/] host(s) found")

    threading.Thread(target=_scanner_loop,
                     args=(state, target, ports, timeout, db_path, rescan, stop),
                     daemon=True).start()

    # always-on ARP-spoof / MITM detector (passive, no admin, works on Wi-Fi)
    def _arp_alert(a):
        state.add_event("arp.alert", {"ipv4": a.get("ip", ""), "hostname": a["msg"]})

    def _arp_loop():
        from . import arpwatch
        arpwatch.watch(interval=6, gateway_ip=state.gateway.get("ipv4", ""),
                       on_alert=_arp_alert, should_stop=stop.is_set)

    threading.Thread(target=_arp_loop, daemon=True).start()
    if monitor_on:
        threading.Thread(target=_monitor_loop,
                         args=(state, state.interface["ipv4"], stop), daemon=True).start()
        output.note("passive monitor thread started (needs Administrator to capture)")

    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    url = f"http://{host}:{port}"
    output.note(f"RECON CONSOLE live at [bold]{url}[/]  (Ctrl-C to stop)")
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        output.note("shutting down")
    finally:
        stop.set()
        httpd.shutdown()

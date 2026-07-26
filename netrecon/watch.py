"""``netrecon watch`` — continuous monitoring with new-device / new-port alerts.

Rescans on an interval, diffs against the accumulated inventory, and raises an
alert (console + optional ntfy.sh push to your phone) when a new device joins or
a new port opens on a known host.
"""

from __future__ import annotations

import time
import urllib.request
from typing import Dict, List, Optional, Set

from . import output, recon, store


def ntfy_url(topic_or_url: str) -> str:
    """A bare topic becomes an ntfy.sh URL; a full URL is used as-is."""
    return topic_or_url if topic_or_url.startswith("http") else f"https://ntfy.sh/{topic_or_url}"


def notify_ntfy(topic_or_url: str, title: str, message: str) -> bool:
    """Push a notification via ntfy (topic name or full URL). No account needed."""
    url = ntfy_url(topic_or_url)
    req = urllib.request.Request(
        url, data=message.encode("utf-8"),
        headers={"Title": title, "Priority": "high", "Tags": "warning"},
    )
    try:
        urllib.request.urlopen(req, timeout=6)
        return True
    except Exception:
        return False


def _alert(ntfy: Optional[str], title: str, msg: str) -> None:
    output.note(f"[bold red]ALERT[/] {title}: {msg}")
    if ntfy:
        notify_ntfy(ntfy, f"netrecon: {title}", msg)


def _host_key(mac: str, ip: str) -> str:
    return mac or ("ip:" + ip)


def watch(target: str, ports: Optional[List[int]] = None, timeout: float = 0.6,
          interval: int = 60, ntfy: Optional[str] = None,
          db_path: Optional[str] = None, once: bool = False) -> None:
    db_path = db_path or store.DEFAULT_DB
    con = store.connect(db_path)
    known_hosts: Set[str] = {r["mac"] for r in store.list_hosts(con)}
    known_ports: Dict[str, Set[int]] = {
        r["mac"]: {p["port"] for p in store.ports_for(con, r["mac"])}
        for r in store.list_hosts(con)
    }
    con.close()

    baseline_empty = not known_hosts  # suppress alert storm on a first-ever run
    output.note(f"watching [bold]{target}[/] every {interval}s "
                f"({'ntfy: ' + ntfy if ntfy else 'console alerts'}) ... Ctrl-C to stop")

    first = True
    while True:
        hosts = recon.gather(target, ports, timeout)
        for h in hosts:
            key = _host_key(h["mac"], h["ip"])
            portset = {p["port"] for p in h["ports"]}
            label = h.get("hostname") or h.get("vendor") or h["mac"] or h["ip"]
            if key not in known_hosts:
                if not (first and baseline_empty):
                    _alert(ntfy, "New device", f"{h['ip']} {label}")
                known_hosts.add(key)
                known_ports[key] = portset
            else:
                new_ports = portset - known_ports.get(key, set())
                if new_ports and not (first and baseline_empty):
                    _alert(ntfy, "New ports", f"{h['ip']} {label} opened {sorted(new_ports)}")
                known_ports[key] = known_ports.get(key, set()) | portset

        con = store.connect(db_path)
        store.save_scan(con, target, [
            {"ip": h["ip"], "mac": h["mac"], "hostname": h["hostname"], "vendor": h["vendor"],
             "ports": [{"port": p["port"], "service": p["service"], "banner": ""} for p in h["ports"]]}
            for h in hosts
        ])
        con.close()

        if first:
            output.note(f"baseline: {len(hosts)} host(s) - alerting on changes from here")
        first = False
        if once:
            break
        time.sleep(interval)

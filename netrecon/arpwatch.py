"""Passive ARP-spoofing / MITM detector.

Watches the OS ARP cache for IP->MAC changes — no admin, no Scapy, works on
Wi-Fi. A gateway MAC change is a strong sign of an active ARP-spoof MITM; a
single MAC answering for many IPs is a classic spoofer signature. `analyze` is
a pure function so it unit-tests without touching the network.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from . import discovery


def analyze(prev: Dict[str, str], current: Dict[str, str], gateway_ip: str = "") -> List[dict]:
    """Return alert dicts for suspicious ARP changes between two snapshots."""
    alerts: List[dict] = []
    for ip, mac in current.items():
        old = prev.get(ip)
        if old and old != mac:
            is_gw = ip == gateway_ip
            alerts.append({
                "kind": "mac-change", "ip": ip, "old": old, "new": mac,
                "severity": 1 if is_gw else 2,
                "msg": f"{ip} MAC changed {old} -> {mac}"
                       + (" (GATEWAY - likely active MITM!)" if is_gw else ""),
            })
    by_mac: Dict[str, List[str]] = {}
    for ip, mac in current.items():
        by_mac.setdefault(mac, []).append(ip)
    for mac, ips in by_mac.items():
        if len(ips) >= 3:  # one MAC claiming many IPs = classic spoofer
            alerts.append({
                "kind": "mac-impersonation", "mac": mac, "ips": ips, "severity": 2,
                "msg": f"{mac} is claiming {len(ips)} IPs "
                       f"({', '.join(ips[:6])}{'…' if len(ips) > 6 else ''}) - possible spoofer",
            })
    return alerts


def watch(interval: int = 5, gateway_ip: str = "",
          on_alert: Optional[Callable[[dict], None]] = None,
          iterations: Optional[int] = None,
          should_stop: Optional[Callable[[], bool]] = None) -> None:
    """Poll the ARP cache and fire `on_alert` on each suspicious change."""
    prev = discovery.arp_table()
    n = 0
    while True:
        if should_stop and should_stop():
            break
        time.sleep(interval)
        current = discovery.arp_table()
        if on_alert:
            for a in analyze(prev, current, gateway_ip):
                on_alert(a)
        prev = current
        n += 1
        if iterations and n >= iterations:
            break

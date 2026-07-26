"""Shared recon primitive: discover + scan + enrich into host dicts."""

from __future__ import annotations

from typing import List, Optional

from . import discovery, enrich, net, scanner


def gather(target: str, ports: Optional[List[int]] = None, timeout: float = 0.6,
           banners: bool = False, workers: int = 128, ping_timeout: int = 700,
           concurrency: int = 400) -> List[dict]:
    """Discover live hosts on `target`, scan their ports, and enrich.

    Returns a list of host dicts:
        {ip, mac, vendor, hostname, ports:[{port, service, banner}]}
    """
    ports = ports or scanner.TOP_PORTS
    targets = net.expand_targets(target)
    live = set(discovery.discover(targets, workers=workers, timeout_ms=ping_timeout))
    arp = discovery.arp_table()
    tset = set(targets)
    live.update(ip for ip in arp if ip in tset)  # ping-silent but ARP-known
    live_sorted = net.sort_ips(live)

    scan_res = scanner.scan(live_sorted, ports, timeout=timeout, concurrency=concurrency)

    hosts: List[dict] = []
    for ip in live_sorted:
        mac = arp.get(ip, "")
        host = {
            "ip": ip,
            "mac": mac,
            "vendor": enrich.vendor(mac) if mac else "",
            "hostname": enrich.hostname(ip),
            "ports": [],
        }
        for p in scan_res.get(ip, []):
            host["ports"].append({
                "port": p,
                "service": enrich.service_name(p),
                "banner": enrich.banner(ip, p) if banners else "",
            })
        hosts.append(host)
    return hosts

"""Network helpers: local IP, subnet detection, target expansion."""

from __future__ import annotations

import ipaddress
import socket
from typing import List


def local_ipv4() -> str:
    """Best-effort primary IPv4 of this host (no packets are actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_subnet(prefix: int = 24) -> str:
    """Auto-detected local subnet in CIDR form, e.g. '192.168.88.0/24'."""
    ip = local_ipv4()
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(net)


def expand_targets(spec: str) -> List[str]:
    """Expand a target spec into a list of host IPs.

    Accepts:
      * a CIDR:          192.168.1.0/24
      * a single IP:     192.168.1.10
      * a last-octet range: 192.168.1.10-50
      * a full IP range:    192.168.1.10-192.168.1.50
    """
    spec = spec.strip()
    if "/" in spec:
        return [str(h) for h in ipaddress.ip_network(spec, strict=False).hosts()]
    if "-" in spec:
        start, end = (p.strip() for p in spec.split("-", 1))
        if "." in end:  # full IP range
            lo = int(ipaddress.ip_address(start))
            hi = int(ipaddress.ip_address(end))
            return [str(ipaddress.ip_address(i)) for i in range(lo, hi + 1)]
        base, last = start.rsplit(".", 1)  # last-octet range
        return [f"{base}.{i}" for i in range(int(last), int(end) + 1)]
    return [str(ipaddress.ip_address(spec))]


def sort_ips(ips):
    """Sort dotted-quad IPs numerically."""
    return sorted(ips, key=lambda x: tuple(int(o) for o in x.split(".")))

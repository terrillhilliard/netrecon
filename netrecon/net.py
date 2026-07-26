"""Network helpers: local IP, subnet detection, target expansion."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Dict, List, Optional

_IS_WIN = platform.system().lower().startswith("win")
_VIRTUAL = re.compile(
    r"vmware|virtualbox|hyper-v|loopback|proton|tunnel|vethernet|bluetooth|wsl|tap|vpn|wireguard|docker",
    re.I,
)
_WIRELESS = re.compile(r"wi-?fi|wlan|wireless|802\.11", re.I)


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


def subnet_for(ip: str, prefix: int = 24) -> str:
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _looks_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _ifaces_windows() -> List[Dict[str, str]]:
    try:
        raw = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: List[Dict[str, str]] = []
    cur: Optional[Dict[str, str]] = None
    for line in raw.splitlines():
        if line and not line[0].isspace():
            m = re.match(r".*adapter (.+):$", line.strip())
            if cur:
                out.append(cur)
                cur = None
            if m:
                cur = {"name": m.group(1).strip(), "ipv4": "", "mac": "", "gateway": ""}
            continue
        if cur is None:
            continue
        s = line.strip()
        if "Physical Address" in s:
            mm = re.search(r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}", s)
            if mm:
                cur["mac"] = mm.group(0).lower().replace("-", ":")
        elif "IPv4 Address" in s and not cur["ipv4"]:
            mm = re.search(r"(\d{1,3}\.){3}\d{1,3}", s)
            if mm:
                cur["ipv4"] = mm.group(0)
        elif "Default Gateway" in s and not cur["gateway"]:
            mm = re.search(r"(\d{1,3}\.){3}\d{1,3}", s)
            if mm:
                cur["gateway"] = mm.group(0)
    if cur:
        out.append(cur)
    return [i for i in out if i["ipv4"]]


def _ifaces_posix() -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        raw = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=8
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return out
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            out.append({"name": parts[1], "ipv4": parts[3].split("/")[0], "mac": "", "gateway": ""})
    return out


def list_interfaces() -> List[Dict]:
    """Enumerate interfaces with an IPv4, flagged virtual/wireless."""
    ifs = _ifaces_windows() if _IS_WIN else _ifaces_posix()
    for i in ifs:
        i["virtual"] = bool(_VIRTUAL.search(i["name"]))
        i["wireless"] = bool(_WIRELESS.search(i["name"]))
        i["apipa"] = i["ipv4"].startswith("169.254.")
    return ifs


def select_interface(pref: Optional[str] = None) -> Dict:
    """Choose an interface. `pref` matches by name (substring) or IP; otherwise
    auto-pick, preferring a physical adapter with a gateway, wired over wireless."""
    ifs = list_interfaces()
    if pref:
        for i in ifs:
            if (i["name"].lower() == pref.lower() or i["ipv4"] == pref
                    or pref.lower() in i["name"].lower()):
                return i
        return {"name": pref, "ipv4": pref if _looks_ip(pref) else local_ipv4(),
                "mac": "", "gateway": "", "virtual": False, "wireless": False, "apipa": False}

    def score(i: Dict) -> int:
        s = 0
        if i.get("gateway"):
            s += 100
        if not i.get("virtual"):
            s += 50
        if not i.get("wireless"):  # prefer wired (eth) over wireless (wlan)
            s += 10
        if not i.get("apipa"):
            s += 20
        return s

    cands = [i for i in ifs if i["ipv4"] and not i["apipa"]]
    if cands:
        return sorted(cands, key=score, reverse=True)[0]
    return {"name": "auto", "ipv4": local_ipv4(), "mac": "", "gateway": "",
            "virtual": False, "wireless": False, "apipa": False}

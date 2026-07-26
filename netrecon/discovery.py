"""Host discovery via concurrent ping sweep + OS ARP-cache resolution.

Uses subprocess `ping` (works without administrator privileges on Windows,
Linux and macOS) plus the system ARP table to recover MAC addresses. Hosts
that are silent to ping but already known to the ARP cache are still surfaced.
"""

from __future__ import annotations

import concurrent.futures as cf
import platform
import re
import subprocess
from typing import Dict, List

_IS_WIN = platform.system().lower().startswith("win")
_MAC_RE = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)
_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def ping(ip: str, timeout_ms: int = 700) -> bool:
    if _IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 1.5,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def discover(targets: List[str], workers: int = 128, timeout_ms: int = 700) -> List[str]:
    """Return the subset of `targets` that respond to ping."""
    live: List[str] = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(ping, ip, timeout_ms): ip for ip in targets}
        for fut in cf.as_completed(futures):
            try:
                if fut.result():
                    live.append(futures[fut])
            except Exception:
                pass
    return live


def arp_table() -> Dict[str, str]:
    """Map ip -> normalized lowercase MAC from the OS ARP cache."""
    out: Dict[str, str] = {}
    try:
        raw = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=8
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return out
    for line in raw.splitlines():
        ipm = _IP_RE.search(line)
        macm = _MAC_RE.search(line)
        if ipm and macm:
            mac = macm.group(0).lower().replace("-", ":")
            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                out[ipm.group(0)] = mac
    return out

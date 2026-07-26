"""Async TCP connect port scanner (no raw sockets, no admin required)."""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

# A curated "top ports" set — good coverage for a fast default scan.
TOP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 67, 80, 88, 110, 111, 123, 135, 137, 139, 143, 161,
    389, 443, 445, 465, 514, 515, 548, 587, 631, 636, 993, 995, 1025, 1080,
    1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2222, 2375, 3128, 3268,
    3306, 3389, 3690, 4444, 5000, 5060, 5222, 5353, 5432, 5555, 5601, 5672,
    5900, 5985, 5986, 6379, 6443, 6667, 7000, 7070, 8000, 8006, 8008, 8080,
    8081, 8083, 8088, 8123, 8443, 8500, 8888, 9000, 9090, 9100, 9200, 9300,
    10000, 11211, 27017, 32400,
]


async def _check(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> Optional[int]:
    async with sem:
        writer = None
        try:
            fut = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(fut, timeout=timeout)
            return port
        except (asyncio.TimeoutError, OSError):
            return None
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass


async def _scan_all(hosts, ports, timeout, concurrency):
    sem = asyncio.Semaphore(concurrency)
    result: Dict[str, List[int]] = {ip: [] for ip in hosts}

    async def one(ip, port):
        return ip, await _check(ip, port, timeout, sem)

    tasks = [asyncio.create_task(one(ip, p)) for ip in hosts for p in ports]
    for coro in asyncio.as_completed(tasks):
        ip, port = await coro
        if port is not None:
            result[ip].append(port)
    for ip in result:
        result[ip].sort()
    return result


def scan(
    hosts: List[str],
    ports: Optional[List[int]] = None,
    timeout: float = 0.6,
    concurrency: int = 400,
) -> Dict[str, List[int]]:
    """Return {ip: [open_ports]} for the given hosts."""
    ports = ports or TOP_PORTS
    if not hosts:
        return {}
    return asyncio.run(_scan_all(hosts, ports, timeout, concurrency))

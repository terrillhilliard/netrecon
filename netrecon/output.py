"""Console output (rich tables with a graceful plain-text fallback) + JSON."""

from __future__ import annotations

import json
from typing import List

from .net import sort_ips


def _plain(hosts: List[dict]) -> str:
    rows = [f"{'IP':16}{'MAC':19}{'VENDOR':24}{'HOSTNAME':22}PORTS"]
    for h in sorted(hosts, key=lambda x: tuple(int(o) for o in x["ip"].split("."))):
        ports = ", ".join(f"{p['port']}/{p.get('service') or 'tcp'}" for p in h.get("ports", []))
        rows.append(
            f"{h['ip']:16}{h.get('mac',''):19}{(h.get('vendor','') or '-')[:23]:24}"
            f"{(h.get('hostname','') or '-')[:21]:22}{ports}"
        )
    return "\n".join(rows)


def print_hosts(hosts: List[dict]) -> None:
    try:
        from rich import box
        from rich.console import Console
        from rich.table import Table

        table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", pad_edge=False)
        table.add_column("IP", style="bold")
        table.add_column("MAC", style="dim")
        table.add_column("Vendor")
        table.add_column("Hostname")
        table.add_column("Open Ports", style="green")
        order = {ip: i for i, ip in enumerate(sort_ips(h["ip"] for h in hosts))}
        for h in sorted(hosts, key=lambda x: order[x["ip"]]):
            ports = ", ".join(
                f"{p['port']}/{p.get('service') or 'tcp'}" for p in h.get("ports", [])
            )
            table.add_row(
                h["ip"],
                h.get("mac", "") or "[dim]—[/]",
                h.get("vendor", "") or "[dim]—[/]",
                h.get("hostname", "") or "[dim]—[/]",
                ports or "[dim]none[/]",
            )
        Console().print(table)
    except ImportError:
        print(_plain(hosts))


def _strip_markup(text: str) -> str:
    import re

    return re.sub(r"\[/?[a-z0-9 #]*\]", "", text)


def print_summary(target: str, hosts: List[dict], elapsed: float) -> None:
    n_ports = sum(len(h.get("ports", [])) for h in hosts)
    msg = f"{len(hosts)} hosts up | {n_ports} open ports | {elapsed:.1f}s | target {target}"
    try:
        from rich.console import Console

        Console().print(f"[bold green]OK[/] {msg}")
    except ImportError:
        print("[+] " + _strip_markup(msg))


def note(msg: str) -> None:
    try:
        from rich.console import Console

        Console().print(f"[cyan]>[/] {msg}")
    except ImportError:
        print("[*] " + _strip_markup(msg))


def to_json(hosts: List[dict]) -> str:
    return json.dumps(hosts, indent=2)

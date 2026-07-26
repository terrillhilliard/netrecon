"""netrecon command-line interface."""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from . import __version__, discovery, enrich, net, output, scanner, store


def _resolve_ports(args) -> List[int]:
    if args.full:
        return list(range(1, 65536))
    if args.ports:
        out: List[int] = []
        for part in args.ports.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                out.extend(range(int(a), int(b) + 1))
            else:
                out.append(int(part))
        return out
    return scanner.TOP_PORTS


def cmd_scan(args) -> None:
    target = args.target or net.default_subnet()
    targets = net.expand_targets(target)
    output.note(f"discovering {len(targets)} address(es) on [bold]{target}[/] ...")

    t0 = time.time()
    live = set(discovery.discover(targets, workers=args.workers, timeout_ms=args.ping_timeout))
    arp = discovery.arp_table()
    # add ping-silent hosts that the ARP cache already knows about
    tset = set(targets)
    live.update(ip for ip in arp if ip in tset)
    live_sorted = net.sort_ips(live)

    if not live_sorted:
        output.note("no live hosts found (try --ping-timeout 1200 or check the interface).")
        return

    output.note(f"[green]{len(live_sorted)}[/] host(s) up - scanning "
                f"{'all 65535' if args.full else len(_resolve_ports(args))} ports each ...")
    ports = _resolve_ports(args)
    scan_res = scanner.scan(live_sorted, ports, timeout=args.timeout, concurrency=args.concurrency)

    hosts = []
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
                "banner": enrich.banner(ip, p) if args.banners else "",
            })
        hosts.append(host)

    elapsed = time.time() - t0

    if args.json:
        print(output.to_json(hosts))
    else:
        output.print_hosts(hosts)
        output.print_summary(target, hosts, elapsed)

    if not args.no_store:
        con = store.connect(args.db)
        store.save_scan(con, target, hosts)
        con.close()
        if not args.json:
            output.note(f"saved to [dim]{args.db}[/]")


def cmd_hosts(args) -> None:
    con = store.connect(args.db)
    rows = store.list_hosts(con)
    hosts = []
    for r in rows:
        ports = [{"port": p["port"], "service": p["service"], "banner": p["banner"]}
                 for p in store.ports_for(con, r["mac"])]
        hosts.append({
            "ip": r["ip"], "mac": "" if r["mac"].startswith("ip:") else r["mac"],
            "vendor": r["vendor"], "hostname": r["hostname"], "ports": ports,
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
        })
    con.close()
    if args.json:
        print(output.to_json(hosts))
    else:
        output.print_hosts(hosts)
        output.note(f"{len(hosts)} host(s) in inventory [dim]{args.db}[/]")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netrecon",
        description="Network reconnaissance, asset inventory & monitoring CLI.",
    )
    p.add_argument("--version", action="version", version=f"netrecon {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="discover live hosts and scan their ports")
    s.add_argument("target", nargs="?", help="CIDR, IP, or range (default: auto-detected /24)")
    s.add_argument("--ports", help="port list e.g. 22,80,443,8000-8100")
    s.add_argument("--full", action="store_true", help="scan all 65535 ports")
    s.add_argument("--timeout", type=float, default=0.6, help="per-port connect timeout, s (default 0.6)")
    s.add_argument("--concurrency", type=int, default=400, help="max concurrent connections (default 400)")
    s.add_argument("--workers", type=int, default=128, help="ping-sweep workers (default 128)")
    s.add_argument("--ping-timeout", type=int, default=700, help="ping timeout, ms (default 700)")
    s.add_argument("--banners", action="store_true", help="grab service banners on open ports")
    s.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    s.add_argument("--db", default=store.DEFAULT_DB, help="SQLite inventory path")
    s.add_argument("--no-store", action="store_true", help="do not persist results")
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("hosts", help="list the accumulated asset inventory")
    h.add_argument("--db", default=store.DEFAULT_DB, help="SQLite inventory path")
    h.add_argument("--json", action="store_true")
    h.set_defaults(func=cmd_hosts)

    return p


def main(argv: Optional[List[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()

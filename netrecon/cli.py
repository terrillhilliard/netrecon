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
    iface = net.select_interface(getattr(args, "iface", None))
    target = args.target or net.subnet_for(iface["ipv4"])
    output.note(f"interface [bold]{iface['name']}[/] ({iface['ipv4']})")
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


def cmd_monitor(args) -> None:
    import collections

    from . import monitor

    flows = collections.defaultdict(lambda: {"packets": 0, "bytes": 0})
    dnsq: "collections.Counter" = collections.Counter()
    counter = {"pkts": 0}

    def on_pkt(proto, src, dst, sport, dport, length):
        counter["pkts"] += 1
        key = (src, dst, monitor.proto_name(proto), dport or 0)
        f = flows[key]
        f["packets"] += 1
        f["bytes"] += length

    def on_dns(client, server, qname):
        dnsq[(client, qname)] += 1

    iface = net.select_interface(getattr(args, "iface", None))
    dur = f" for {args.duration}s" if args.duration else ""
    output.note(f"capturing on [bold]{iface['name']}[/] ({iface['ipv4']}){dur} ... (Ctrl-C to stop)")
    try:
        monitor.capture(on_pkt, on_dns, duration=args.duration, iface_ip=iface["ipv4"])
    except PermissionError:
        output.note("raw capture needs Administrator - re-run in an elevated shell.")
        return
    except RuntimeError as e:
        output.note(str(e))
        return
    except KeyboardInterrupt:
        pass

    output.note(f"{counter['pkts']} packets | {len(flows)} flows | {len(dnsq)} DNS names")
    flow_rows = sorted(
        ({"src": k[0], "dst": k[1], "proto": k[2], "dport": k[3], **v} for k, v in flows.items()),
        key=lambda r: r["bytes"], reverse=True,
    )[: args.top]
    dns_rows = [{"client": k[0], "qname": k[1], "hits": v} for k, v in dnsq.most_common(args.top)]

    if args.json:
        print(output.to_json({"flows": flow_rows, "dns": dns_rows}))
    else:
        if flow_rows:
            output.print_flows(flow_rows)
        if dns_rows:
            output.print_dns(dns_rows)

    if not args.no_store and (flows or dnsq):
        con = store.connect(args.db)
        store.save_flows(con, dict(flows))
        store.save_dns(con, dict(dnsq))
        con.close()
        if not args.json:
            output.note(f"saved to [dim]{args.db}[/]")


def cmd_serve(args) -> None:
    from . import serve as serve_mod

    iface = net.select_interface(getattr(args, "iface", None))
    ports = _resolve_ports(args) if (args.ports or args.full) else None
    serve_mod.serve(
        host=args.host, port=args.port, target=args.target, ports=ports,
        timeout=args.timeout, db_path=args.db, rescan=args.rescan,
        monitor_on=args.monitor, open_browser=not args.no_browser, iface=iface,
    )


def cmd_interfaces(args) -> None:
    ifs = net.list_interfaces()
    chosen = net.select_interface(getattr(args, "iface", None))
    if args.json:
        print(output.to_json(ifs))
        return
    try:
        from rich import box
        from rich.console import Console
        from rich.table import Table

        t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", pad_edge=False)
        for col in ("", "Interface", "IPv4", "MAC", "Gateway", "Type"):
            t.add_column(col)
        for i in ifs:
            kind = "virtual" if i["virtual"] else ("wireless" if i["wireless"] else "wired")
            mark = "[green]*[/]" if i["ipv4"] == chosen["ipv4"] else " "
            t.add_row(mark, i["name"], i["ipv4"], i.get("mac", "") or "[dim]—[/]",
                      i.get("gateway", "") or "[dim]—[/]", kind)
        Console().print(t)
        Console().print(f"[dim]* = default selection ([bold]{chosen['name']}[/]). "
                        f"Override with --iface <name|ip>.[/]")
    except ImportError:
        for i in ifs:
            mark = "*" if i["ipv4"] == chosen["ipv4"] else " "
            print(f"{mark} {i['name']:28} {i['ipv4']:16} gw={i.get('gateway','') or '-'}")
        print(f"* default = {chosen['name']}; override with --iface <name|ip>")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netrecon",
        description="Network reconnaissance, asset inventory & monitoring CLI.",
    )
    p.add_argument("--version", action="version", version=f"netrecon {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="discover live hosts and scan their ports")
    s.add_argument("target", nargs="?", help="CIDR, IP, or range (default: selected iface /24)")
    s.add_argument("--iface", help="interface name or IP to use (default: auto — wired > wireless)")
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

    m = sub.add_parser("monitor", help="passively capture flows + DNS (raw socket; needs admin)")
    m.add_argument("--iface", help="interface name or IP to capture on (default: auto)")
    m.add_argument("--duration", type=float, help="seconds to capture (default: until Ctrl-C)")
    m.add_argument("--top", type=int, default=25, help="rows to show (default 25)")
    m.add_argument("--json", action="store_true")
    m.add_argument("--db", default=store.DEFAULT_DB)
    m.add_argument("--no-store", action="store_true")
    m.set_defaults(func=cmd_monitor)

    v = sub.add_parser("serve", help="serve the RECON CONSOLE dashboard on the netrecon engine")
    v.add_argument("target", nargs="?", help="CIDR/IP/range to monitor (default: selected iface /24)")
    v.add_argument("--iface", help="interface name or IP to bind (default: auto)")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8081)
    v.add_argument("--ports", help="port list for scans e.g. 22,80,443")
    v.add_argument("--full", action="store_true", help="scan all 65535 ports")
    v.add_argument("--timeout", type=float, default=0.6)
    v.add_argument("--rescan", type=int, default=60, help="rescan interval, s (default 60)")
    v.add_argument("--monitor", action="store_true", help="also run passive capture (needs admin)")
    v.add_argument("--db", default=store.DEFAULT_DB)
    v.add_argument("--no-browser", action="store_true", help="don't auto-open a browser")
    v.set_defaults(func=cmd_serve)

    i = sub.add_parser("interfaces", help="list network interfaces and the auto-selected default")
    i.add_argument("--iface", help="show which interface this preference would select")
    i.add_argument("--json", action="store_true")
    i.set_defaults(func=cmd_interfaces)

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

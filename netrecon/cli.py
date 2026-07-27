"""netrecon command-line interface."""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from . import __version__, net, output, recon, scanner, store


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
    ports = _resolve_ports(args)
    output.note(f"scanning [bold]{target}[/] - "
                f"{'all 65535' if args.full else len(ports)} ports/host ...")

    t0 = time.time()
    hosts = recon.gather(target, ports, timeout=args.timeout, banners=args.banners,
                         workers=args.workers, ping_timeout=args.ping_timeout,
                         concurrency=args.concurrency)
    elapsed = time.time() - t0

    if not hosts:
        output.note("no live hosts found (try --ping-timeout 1200 or check the interface).")
        return

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
        ai_key=args.ai_key, ai_model=args.ai_model, vt_key=args.vt_key, ha_key=args.ha_key,
        nvd_key=args.nvd_key,
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


def cmd_watch(args) -> None:
    from . import watch as watch_mod

    iface = net.select_interface(getattr(args, "iface", None))
    target = args.target or net.subnet_for(iface["ipv4"])
    ports = _resolve_ports(args)
    output.note(f"interface [bold]{iface['name']}[/] ({iface['ipv4']})")
    try:
        watch_mod.watch(target, ports, timeout=args.timeout, interval=args.interval,
                        ntfy=args.ntfy, db_path=args.db, once=args.once)
    except KeyboardInterrupt:
        output.note("stopped")


def cmd_ingest(args) -> None:
    import glob
    import os
    from pathlib import Path

    from . import ingest

    paths: List[str] = []
    for pat in args.paths:
        if os.path.isdir(pat):
            for ext in ("*.log", "*.json"):
                paths += [str(p) for p in Path(pat).glob(ext)]
        else:
            paths += glob.glob(pat) or [pat]

    con = store.connect(args.db)
    total = {"alerts": 0, "flows": 0, "dns": 0}
    for path in paths:
        fmt = args.format or ingest.detect_format(path)
        try:
            c = ingest.ingest_file(path, fmt, con)
        except OSError as e:
            output.note(f"skip {path}: {e}")
            continue
        total = {k: total[k] + c[k] for k in total}
        output.note(f"{os.path.basename(path)} ({fmt}) -> "
                    f"{c['alerts']} alerts, {c['flows']} flows, {c['dns']} dns")
    con.close()
    output.note(f"[green]done[/] - {total['alerts']} alerts, {total['flows']} flows, "
                f"{total['dns']} dns into [dim]{args.db}[/]")


def cmd_alerts(args) -> None:
    con = store.connect(args.db)
    rows = [dict(r) for r in store.recent_alerts(con, limit=args.limit, min_severity=args.severity)]
    con.close()
    if args.json:
        print(output.to_json(rows))
    else:
        if rows:
            output.print_alerts(rows)
        output.note(f"{len(rows)} alert(s) in [dim]{args.db}[/]")


def cmd_mitm(args) -> None:
    import collections
    import time as _t

    from . import mitm

    iface = net.select_interface(getattr(args, "iface", None))
    gw = args.gateway or iface.get("gateway")
    if not gw:
        output.note("could not determine the gateway - pass --gateway <ip>")
        return

    flows = collections.defaultdict(lambda: {"packets": 0, "bytes": 0})
    dnsq: "collections.Counter" = collections.Counter()

    def on_flow(src, dst, proto, dport, length):
        f = flows[(src, dst, proto, dport or 0)]
        f["packets"] += 1
        f["bytes"] += length

    def on_dns(client, qname):
        dnsq[(client, qname)] += 1
        output.note(f"DNS  {client} -> {qname}")

    def on_http(client, host):
        output.note(f"HTTP {client} -> {host}")

    sess = mitm.MitmSession(args.target, gw, iface_ip=iface["ipv4"],
                            on_flow=on_flow, on_dns=on_dns, on_http=on_http)
    output.note(f"[bold red]MITM[/] {args.target} <-> {gw} on {iface['name']} - "
                f"forwarding + capturing. Ctrl-C to stop.")
    output.note("only run against devices you own or are authorized to test.")
    try:
        sess.start()
        while True:
            _t.sleep(3)
            output.note(f"{sess.stats['packets']} pkts | {sess.stats['forwarded']} forwarded | "
                        f"{sess.stats['dns']} dns")
    except KeyboardInterrupt:
        pass
    except ImportError:
        output.note("MITM needs scapy - run: pip install scapy")
        return
    except RuntimeError as e:
        output.note(str(e))
        return
    except (PermissionError, OSError) as e:
        output.note(f"MITM needs Administrator + Npcap: {e}")
        return
    finally:
        output.note("restoring ARP tables ...")
        try:
            sess.stop()
        except Exception:
            pass

    con = store.connect(args.db)
    store.save_flows(con, dict(flows))
    store.save_dns(con, dict(dnsq))
    con.close()
    output.note(f"[green]saved[/] {len(flows)} flows, {len(dnsq)} DNS names to [dim]{args.db}[/]")
    output.note("view with: netrecon flows   |   netrecon dns")


def cmd_flows(args) -> None:
    con = store.connect(args.db)
    rows = [dict(r) for r in store.top_flows(con, args.limit)]
    con.close()
    if args.json:
        print(output.to_json(rows))
    else:
        if rows:
            output.print_flows(rows)
        output.note(f"{len(rows)} flow(s) in [dim]{args.db}[/]")


def cmd_dns(args) -> None:
    con = store.connect(args.db)
    rows = [dict(r) for r in store.recent_dns(con, args.limit)]
    con.close()
    if args.json:
        print(output.to_json(rows))
    else:
        if rows:
            output.print_dns(rows)
        output.note(f"{len(rows)} DNS name(s) in [dim]{args.db}[/]")


def _print_cves(title, rows) -> None:
    if not rows or rows[0].get("error"):
        output.note(f"{title}: {rows[0].get('error') if rows else 'no CVEs found'}")
        return
    output.note(f"[bold]{title}[/]")
    for c in rows:
        sev = f"{c['severity'] or '?'} {c['score'] if c['score'] is not None else ''}".strip()
        if c.get("kev"):
            mk = " [bold red]* ACTIVELY EXPLOITED[/]"
        elif c.get("exploits"):
            mk = " [yellow]* public exploit[/]"
        else:
            mk = ""
        output.note(f"  {c['id']}  {sev}{mk}  {c['published']} - {c['desc'][:100]}")


def cmd_vulns(args) -> None:
    from . import nvd

    if args.keyword:
        _print_cves(args.keyword, nvd.search(args.keyword, limit=args.limit))
        return
    con = store.connect(args.db)
    hosts = store.list_hosts(con)
    seen, found = set(), False
    for r in hosts:
        for p in store.ports_for(con, r["mac"]):
            kw = nvd.clean_banner(p["banner"] or "")
            if kw and kw not in seen:
                seen.add(kw)
                rows = nvd.search(kw, limit=args.limit)
                if rows and not rows[0].get("error"):
                    _print_cves(f"{r['ip']}  {kw}", rows)
                    found = True
    con.close()
    if not found:
        output.note("no service versions in the inventory - run 'netrecon scan --banners' first")


def cmd_arpwatch(args) -> None:
    from . import arpwatch

    iface = net.select_interface(getattr(args, "iface", None))
    gw = args.gateway or iface.get("gateway") or ""
    output.note(f"watching ARP on [bold]{iface['name']}[/] (gateway {gw or '?'}) "
                f"every {args.interval}s - detects MITM/spoofing. Ctrl-C to stop.")

    def on_alert(a):
        sev = "HIGH" if a.get("severity") == 1 else "MED"
        output.note(f"[bold red]ARP ALERT[/] [{sev}] {a['msg']}")
        if args.ntfy:
            from .watch import notify_ntfy
            notify_ntfy(args.ntfy, f"netrecon ARP alert ({sev})", a["msg"])

    try:
        arpwatch.watch(interval=args.interval, gateway_ip=gw, on_alert=on_alert)
    except KeyboardInterrupt:
        output.note("stopped")


def cmd_gui(args) -> None:
    from . import gui
    gui.main()


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
    v.add_argument("--ai-key", help="Anthropic API key for the AI ANALYSIS tab (else $ANTHROPIC_API_KEY)")
    v.add_argument("--ai-model", help="AI model id (default: claude-sonnet-5)")
    v.add_argument("--vt-key", help="VirusTotal API key for THREAT INTEL (else $VT_API_KEY)")
    v.add_argument("--ha-key", help="Hybrid Analysis API key for THREAT INTEL (else $HYBRID_ANALYSIS_KEY)")
    v.add_argument("--nvd-key", help="NVD API key for live CVE lookups in the AI tab (else $NVD_API_KEY)")
    v.set_defaults(func=cmd_serve)

    w = sub.add_parser("watch", help="continuously scan and alert on new devices / new ports")
    w.add_argument("target", nargs="?", help="CIDR/IP/range (default: selected iface /24)")
    w.add_argument("--iface", help="interface name or IP (default: auto)")
    w.add_argument("--interval", type=int, default=60, help="seconds between scans (default 60)")
    w.add_argument("--ntfy", help="ntfy topic or URL for phone push alerts")
    w.add_argument("--ports", help="port list e.g. 22,80,443")
    w.add_argument("--full", action="store_true", help="scan all 65535 ports")
    w.add_argument("--timeout", type=float, default=0.6)
    w.add_argument("--db", default=store.DEFAULT_DB)
    w.add_argument("--once", action="store_true", help="one pass then exit (sets baseline)")
    w.set_defaults(func=cmd_watch)

    mi = sub.add_parser("mitm", help="ARP-spoof MITM a device + capture/analyze its traffic (admin)")
    mi.add_argument("target", help="target device IP to intercept")
    mi.add_argument("--gateway", help="gateway IP (default: from the selected interface)")
    mi.add_argument("--iface", help="interface name or IP (default: auto)")
    mi.add_argument("--db", default=store.DEFAULT_DB)
    mi.set_defaults(func=cmd_mitm)

    fl = sub.add_parser("flows", help="show captured traffic flows (top talkers)")
    fl.add_argument("--limit", type=int, default=30)
    fl.add_argument("--json", action="store_true")
    fl.add_argument("--db", default=store.DEFAULT_DB)
    fl.set_defaults(func=cmd_flows)

    dn = sub.add_parser("dns", help="show captured DNS queries")
    dn.add_argument("--limit", type=int, default=50)
    dn.add_argument("--json", action="store_true")
    dn.add_argument("--db", default=store.DEFAULT_DB)
    dn.set_defaults(func=cmd_dns)

    ig = sub.add_parser("ingest", help="ingest Suricata eve.json / Zeek logs into the store (SIEM)")
    ig.add_argument("paths", nargs="+", help="log files, globs, or directories")
    ig.add_argument("--format", choices=["suricata", "zeek-conn", "zeek-dns"],
                    help="force a format (default: auto-detect per file)")
    ig.add_argument("--db", default=store.DEFAULT_DB)
    ig.set_defaults(func=cmd_ingest)

    al = sub.add_parser("alerts", help="show ingested IDS alerts")
    al.add_argument("--limit", type=int, default=50)
    al.add_argument("--severity", type=int, help="only severity <= N (1=highest)")
    al.add_argument("--json", action="store_true")
    al.add_argument("--db", default=store.DEFAULT_DB)
    al.set_defaults(func=cmd_alerts)

    vu = sub.add_parser("vulns", help="look up live CVEs (NVD) for a service or your whole inventory")
    vu.add_argument("keyword", nargs="?", help="e.g. 'OpenSSH 8.4' (default: scan the inventory's banners)")
    vu.add_argument("--limit", type=int, default=5)
    vu.add_argument("--db", default=store.DEFAULT_DB)
    vu.set_defaults(func=cmd_vulns)

    aw = sub.add_parser("arpwatch", help="detect ARP-spoofing / MITM (passive; works on Wi-Fi, no admin)")
    aw.add_argument("--iface", help="interface name or IP (default: auto)")
    aw.add_argument("--gateway", help="gateway IP to watch (default: from the interface)")
    aw.add_argument("--interval", type=int, default=5, help="seconds between checks (default 5)")
    aw.add_argument("--ntfy", help="ntfy topic or URL for phone push alerts")
    aw.set_defaults(func=cmd_arpwatch)

    sub.add_parser("gui", help="open the point-and-click launcher window").set_defaults(func=cmd_gui)

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

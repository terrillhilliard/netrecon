# netrecon

[![CI](https://github.com/terrillhilliard/netrecon/actions/workflows/ci.yml/badge.svg)](https://github.com/terrillhilliard/netrecon/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Network reconnaissance, asset inventory & monitoring — a fast, dependency-light Python CLI, with a live web console.**

`netrecon` discovers live hosts on a subnet, scans their ports, enriches each
host with MAC-vendor / hostname / service data, passively captures flows + DNS,
and accumulates everything into a local SQLite **asset inventory** that grows
across runs. The core needs **no admin, no Npcap, no third-party packages** — it
uses a concurrent ping sweep, the OS ARP cache, and an async TCP-connect scanner.
An optional `serve` command hosts a real-time web dashboard on top of the same engine.

> Built by **Terrill Hilliard** — IT Support & Security Operations · M.S. Cybersecurity · CySA+ / PenTest+.

---

## Features

- **`scan`** — concurrent ping + ARP host discovery, async TCP port scan, vendor/hostname/service/banner enrichment.
- **`monitor`** — passive flow + DNS capture via raw sockets (pure stdlib; needs admin).
- **`watch`** — continuous rescans that alert on new devices / newly-opened ports (console + optional [ntfy](https://ntfy.sh) phone push).
- **`serve`** — live web console (radar, host drill-down, port scanner, traffic telemetry) served from the netrecon engine.
- **`interfaces`** — list adapters and pick which one to use; auto-prefers wired, skips VPN/virtual, switch with `--iface`.
- **`hosts`** — the accumulated SQLite asset inventory (`first_seen` / `last_seen` / `times_seen`).
- Clean [rich](https://github.com/Textualize/rich) tables with graceful plain-text fallback, or `--json` for pipelines.

## Install

```bash
git clone https://github.com/terrillhilliard/netrecon
cd netrecon
python -m venv .venv
.venv\Scripts\activate        # Windows   (source .venv/bin/activate on *nix)
pip install -e .              # optional extras: rich (color) + mac-vendor-lookup (vendor names)
```

The core runs on pure stdlib even without the optional packages.

## Usage

```bash
netrecon interfaces                        # see adapters + the auto-selected default
netrecon scan                              # scan the selected interface's /24
netrecon scan --iface Wi-Fi                # pick a specific interface (name or IP)
netrecon scan 192.168.1.0/24 --banners     # explicit target + banner grabbing
netrecon scan 10.0.0.1 --full --json       # all 65535 ports, JSON out
netrecon monitor --duration 30             # 30s passive flow + DNS capture (admin)
netrecon watch --interval 30 --ntfy my-lan # rescan every 30s; push new-device alerts to your phone
netrecon serve                             # open the live web dashboard (http://127.0.0.1:8081)
netrecon serve --iface eth0 --monitor      # bind an interface + live traffic capture
netrecon hosts                             # review the accumulated inventory
```

### Example

```
$ netrecon scan
[*] interface Wi-Fi (192.168.88.145)
[*] discovering 254 address(es) on 192.168.88.0/24 ...
[*] 4 host(s) up - scanning 82 ports each ...

  IP              MAC                Vendor    Hostname        Open Ports
  192.168.88.1    b8:29:03:66:e6:3e  —         VNPT.lan        22/ssh, 53/domain, 80/http, 443/https
  192.168.88.145  —                  —         XYZ-ULG.lan     135/msrpc, 139/netbios-ssn, 445/microsoft-ds
  192.168.88.165  cc:98:8b:13:ce:c5  —         —               80/http, 8008/tcp, 8443/https-alt, 9000/tcp
  192.168.88.174  ae:56:bc:24:6a:4e  —         Galaxy-A20.lan  —

[+] 4 hosts up | 11 open ports | 8.9s | target 192.168.88.0/24
```

## Web dashboard

`netrecon serve` hosts a self-contained web console (sonar radar, host drill-down,
WiFi/traffic panels, a Zenmap-style port view, and an on-device analyzer) backed
by a bettercap-compatible REST API — so the UI runs entirely on the netrecon
engine. It rescans on an interval and, with `--monitor`, streams live traffic and
DNS events. Data persists to `~/.netrecon/netrecon.db`.

## Roadmap

| Phase | Capability | Status |
|-------|-----------|--------|
| 0.1 | discovery + port scan + SQLite inventory | ✅ done |
| 0.2 | `monitor` — passive flow/DNS capture | ✅ done |
| 0.3 | `watch` — new-device / new-port alerts → ntfy | ✅ done |
| 0.4 | `serve` — web console on the netrecon engine | ✅ done |
| 0.5 | Zeek/Suricata ingest → home SIEM (flow search, threat-intel, anomaly scoring) | planned |

## Legal

Only scan or monitor networks you own or are explicitly authorized to test.
Unauthorized scanning may be illegal in your jurisdiction. This tool is for
defensive security, asset management, and authorized assessment.

MIT © 2026 Terrill Hilliard

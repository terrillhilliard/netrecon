# netrecon

**Network reconnaissance, asset inventory & monitoring — a fast, dependency-light Python CLI.**

`netrecon` discovers live hosts on a subnet, scans their ports, enriches each host
with MAC-vendor / hostname / service data, and accumulates it all into a local
SQLite **asset inventory** that grows across scans. No raw sockets and no
administrator privileges required for the core scan — it uses a concurrent ping
sweep, the OS ARP cache, and an async TCP-connect scanner.

> Built by **Terrill Hilliard** — IT Support & Security Operations · M.S. Cybersecurity · CySA+ / PenTest+.
> The companion **RECON CONSOLE** web dashboard is the visual front-end to this engine.

---

## Features (v0.1)

- **Host discovery** — concurrent ping sweep + ARP-cache resolution (catches ping-silent neighbors).
- **Port scanning** — async TCP-connect scanner, curated top-ports by default, `--full` for all 65535.
- **Enrichment** — MAC → vendor (OUI), reverse-DNS hostname, service names, optional banner grab.
- **Asset inventory** — SQLite store with `first_seen` / `last_seen` / `times_seen` per device.
- **Output** — clean [rich](https://github.com/Textualize/rich) tables, or `--json` for pipelines.

## Install

```bash
git clone https://github.com/terrillhilliard/netrecon
cd netrecon
python -m venv .venv
.venv\Scripts\activate        # Windows   (source .venv/bin/activate on *nix)
pip install -e .
```

## Usage

```bash
# scan your auto-detected /24
netrecon scan

# scan a specific subnet / range / host
netrecon scan 192.168.1.0/24
netrecon scan 192.168.1.10-50 --ports 22,80,443,3389 --banners

# full port sweep of one host, JSON out
netrecon scan 192.168.1.1 --full --json

# review the accumulated inventory
netrecon hosts
```

Data persists to `~/.netrecon/netrecon.db` by default (`--db` to override, `--no-store` to skip).

## Roadmap

| Phase | Capability | Tech |
|-------|-----------|------|
| 0.2 | `monitor` — passive flow/DNS logging | Scapy / pyshark → SQLite |
| 0.3 | `watch` — new-device & new-port alerts | ntfy push |
| 0.4 | Local HTTP API + serve RECON CONSOLE dashboard | stdlib http.server |
| 0.5 | Threat-intel enrichment, anomaly scoring | Zeek/Suricata ingest → home SIEM |

## Legal

Only scan networks you own or are explicitly authorized to test. Unauthorized
scanning may be illegal in your jurisdiction. This tool is for defensive
security, asset management, and authorized assessment.

MIT © 2026 Terrill Hilliard

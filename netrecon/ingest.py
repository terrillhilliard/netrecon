"""Log ingest — the SIEM spine.

Parse security-sensor logs into the netrecon SQLite store so netrecon becomes
the store / query / dashboard layer over best-in-class engines:

  * Suricata  eve.json  (alert / dns / flow events)
  * Zeek      conn.log / dns.log  (JSON-lines format, i.e. `redef LogAscii::use_json=T`)

Parsers are pure functions (line/dict -> normalized dict) so they unit-test
without any log files present.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import store


# ---------- Suricata eve.json ----------

def parse_suricata_line(line: str) -> Optional[Dict]:
    """Return {'kind': 'alert'|'dns'|'flow', ...} or None."""
    line = line.strip()
    if not line:
        return None
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return None
    et = e.get("event_type")
    if et == "alert":
        a = e.get("alert", {})
        return {
            "kind": "alert",
            "ts": e.get("timestamp", ""),
            "src": e.get("src_ip", ""), "sport": e.get("src_port"),
            "dst": e.get("dest_ip", ""), "dport": e.get("dest_port"),
            "proto": e.get("proto", ""),
            "signature": a.get("signature", ""),
            "category": a.get("category", ""),
            "severity": a.get("severity"),
            "source": "suricata",
        }
    if et == "dns":
        d = e.get("dns", {})
        name = d.get("rrname") or (d.get("query", [{}])[0].get("rrname") if d.get("query") else "")
        if not name:
            return None
        return {"kind": "dns", "client": e.get("src_ip", ""), "qname": name}
    if et == "flow":
        f = e.get("flow", {})
        return {
            "kind": "flow", "src": e.get("src_ip", ""), "dst": e.get("dest_ip", ""),
            "proto": (e.get("proto") or "").lower(), "dport": e.get("dest_port") or 0,
            "packets": (f.get("pkts_toserver", 0) + f.get("pkts_toclient", 0)),
            "bytes": (f.get("bytes_toserver", 0) + f.get("bytes_toclient", 0)),
        }
    return None


# ---------- Zeek JSON logs ----------

def parse_zeek_conn(rec: Dict) -> Optional[Dict]:
    if not rec.get("id.orig_h"):
        return None
    return {
        "kind": "flow",
        "src": rec.get("id.orig_h", ""), "dst": rec.get("id.resp_h", ""),
        "proto": (rec.get("proto") or "").lower(), "dport": rec.get("id.resp_p") or 0,
        "packets": (rec.get("orig_pkts", 0) + rec.get("resp_pkts", 0)),
        "bytes": (rec.get("orig_ip_bytes", 0) + rec.get("resp_ip_bytes", 0)),
    }


def parse_zeek_dns(rec: Dict) -> Optional[Dict]:
    q = rec.get("query")
    if not q:
        return None
    return {"kind": "dns", "client": rec.get("id.orig_h", ""), "qname": q}


# ---------- ingest drivers ----------

def _iter_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        yield from fh


def ingest_file(path: str, fmt: str, con) -> Dict[str, int]:
    """Ingest one log file. fmt: 'suricata' | 'zeek-conn' | 'zeek-dns'."""
    p = Path(path)
    counts = {"alerts": 0, "flows": 0, "dns": 0}
    alerts: List[dict] = []
    flows: Dict[tuple, dict] = {}
    dns: Dict[tuple, int] = {}

    for line in _iter_lines(p):
        line = line.strip()
        if not line:
            continue
        if fmt == "suricata":
            rec = parse_suricata_line(line)
        else:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec = parse_zeek_conn(obj) if fmt == "zeek-conn" else parse_zeek_dns(obj)
        if not rec:
            continue
        if rec["kind"] == "alert":
            alerts.append(rec)
        elif rec["kind"] == "flow":
            k = (rec["src"], rec["dst"], rec["proto"], rec["dport"])
            agg = flows.setdefault(k, {"packets": 0, "bytes": 0})
            agg["packets"] += rec.get("packets", 0)
            agg["bytes"] += rec.get("bytes", 0)
        elif rec["kind"] == "dns":
            dns[(rec["client"], rec["qname"])] = dns.get((rec["client"], rec["qname"]), 0) + 1

    if alerts:
        counts["alerts"] = store.save_alerts(con, alerts)
    if flows:
        store.save_flows(con, flows)
        counts["flows"] = len(flows)
    if dns:
        store.save_dns(con, dns)
        counts["dns"] = len(dns)
    return counts


def detect_format(path: str) -> str:
    """Guess the log format from the filename / first line."""
    name = Path(path).name.lower()
    if "eve" in name:
        return "suricata"
    if "conn" in name:
        return "zeek-conn"
    if "dns" in name:
        return "zeek-dns"
    try:
        first = next(_iter_lines(Path(path))).strip()
        obj = json.loads(first)
        if "event_type" in obj:
            return "suricata"
        if "id.orig_h" in obj and "query" in obj:
            return "zeek-dns"
        if "id.orig_h" in obj:
            return "zeek-conn"
    except (StopIteration, json.JSONDecodeError, OSError):
        pass
    return "suricata"

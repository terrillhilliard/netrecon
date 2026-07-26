"""SQLite persistence — asset inventory that accrues across scans."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import List, Optional

DEFAULT_DB = str(Path.home() / ".netrecon" / "netrecon.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts(
  mac        TEXT PRIMARY KEY,
  ip         TEXT,
  hostname   TEXT,
  vendor     TEXT,
  first_seen REAL,
  last_seen  REAL,
  times_seen INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS ports(
  mac       TEXT,
  port      INTEGER,
  proto     TEXT DEFAULT 'tcp',
  service   TEXT,
  banner    TEXT,
  last_seen REAL,
  PRIMARY KEY(mac, port, proto)
);
CREATE TABLE IF NOT EXISTS scans(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         REAL,
  target     TEXT,
  host_count INTEGER,
  open_ports INTEGER
);
CREATE TABLE IF NOT EXISTS flows(
  src TEXT, dst TEXT, proto TEXT, dport INTEGER,
  packets INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
  first_seen REAL, last_seen REAL,
  PRIMARY KEY(src, dst, proto, dport)
);
CREATE TABLE IF NOT EXISTS dns(
  client TEXT, qname TEXT, hits INTEGER DEFAULT 1, last_seen REAL,
  PRIMARY KEY(client, qname)
);
CREATE TABLE IF NOT EXISTS alerts(
  ts TEXT, src TEXT, sport INTEGER, dst TEXT, dport INTEGER, proto TEXT,
  signature TEXT, category TEXT, severity INTEGER, source TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


def connect(db_path: str = DEFAULT_DB) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    return con


def _key(host: dict) -> str:
    return host.get("mac") or ("ip:" + host["ip"])


def save_scan(con: sqlite3.Connection, target: str, hosts: List[dict]) -> None:
    now = time.time()
    open_total = 0
    for h in hosts:
        mac = _key(h)
        exists = con.execute("SELECT 1 FROM hosts WHERE mac=?", (mac,)).fetchone()
        if exists:
            con.execute(
                "UPDATE hosts SET ip=?, hostname=?, vendor=?, last_seen=?, "
                "times_seen=times_seen+1 WHERE mac=?",
                (h["ip"], h.get("hostname", ""), h.get("vendor", ""), now, mac),
            )
        else:
            con.execute(
                "INSERT INTO hosts(mac, ip, hostname, vendor, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?)",
                (mac, h["ip"], h.get("hostname", ""), h.get("vendor", ""), now, now),
            )
        for p in h.get("ports", []):
            open_total += 1
            con.execute(
                "INSERT INTO ports(mac, port, proto, service, banner, last_seen) "
                "VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(mac, port, proto) DO UPDATE SET "
                "service=excluded.service, banner=excluded.banner, last_seen=excluded.last_seen",
                (mac, p["port"], "tcp", p.get("service", ""), p.get("banner", ""), now),
            )
    con.execute(
        "INSERT INTO scans(ts, target, host_count, open_ports) VALUES(?,?,?,?)",
        (now, target, len(hosts), open_total),
    )
    con.commit()


def list_hosts(con: sqlite3.Connection) -> List[sqlite3.Row]:
    con.row_factory = sqlite3.Row
    return con.execute("SELECT * FROM hosts ORDER BY last_seen DESC").fetchall()


def ports_for(con: sqlite3.Connection, mac: str) -> List[sqlite3.Row]:
    con.row_factory = sqlite3.Row
    return con.execute(
        "SELECT * FROM ports WHERE mac=? ORDER BY port", (mac,)
    ).fetchall()


def save_flows(con: sqlite3.Connection, flows: dict) -> None:
    """flows: {(src,dst,proto,dport): {'packets':int,'bytes':int}}"""
    now = time.time()
    for (src, dst, proto, dport), agg in flows.items():
        con.execute(
            "INSERT INTO flows(src,dst,proto,dport,packets,bytes,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(src,dst,proto,dport) DO UPDATE SET "
            "packets=packets+excluded.packets, bytes=bytes+excluded.bytes, last_seen=excluded.last_seen",
            (src, dst, proto, dport, agg["packets"], agg["bytes"], now, now),
        )
    con.commit()


def save_dns(con: sqlite3.Connection, queries: dict) -> None:
    """queries: {(client, qname): hits}"""
    now = time.time()
    for (client, qname), hits in queries.items():
        con.execute(
            "INSERT INTO dns(client,qname,hits,last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(client,qname) DO UPDATE SET hits=hits+excluded.hits, last_seen=excluded.last_seen",
            (client, qname, hits, now),
        )
    con.commit()


def top_flows(con: sqlite3.Connection, limit: int = 25) -> List[sqlite3.Row]:
    con.row_factory = sqlite3.Row
    return con.execute(
        "SELECT * FROM flows ORDER BY bytes DESC LIMIT ?", (limit,)
    ).fetchall()


def recent_dns(con: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    con.row_factory = sqlite3.Row
    return con.execute(
        "SELECT * FROM dns ORDER BY last_seen DESC LIMIT ?", (limit,)
    ).fetchall()


def save_alerts(con: sqlite3.Connection, alerts: List[dict]) -> int:
    rows = [
        (a.get("ts", ""), a.get("src", ""), a.get("sport"), a.get("dst", ""),
         a.get("dport"), a.get("proto", ""), a.get("signature", ""),
         a.get("category", ""), a.get("severity"), a.get("source", ""))
        for a in alerts
    ]
    con.executemany(
        "INSERT INTO alerts(ts,src,sport,dst,dport,proto,signature,category,severity,source) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)", rows,
    )
    con.commit()
    return len(rows)


def recent_alerts(con: sqlite3.Connection, limit: int = 50,
                  min_severity: Optional[int] = None) -> List[sqlite3.Row]:
    con.row_factory = sqlite3.Row
    if min_severity is not None:
        return con.execute(
            "SELECT * FROM alerts WHERE severity IS NOT NULL AND severity<=? "
            "ORDER BY ts DESC LIMIT ?", (min_severity, limit),
        ).fetchall()
    return con.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()

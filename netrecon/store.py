"""SQLite persistence — asset inventory that accrues across scans."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import List

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

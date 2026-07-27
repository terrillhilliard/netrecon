"""Live CVE lookups against the NIST NVD REST API 2.0 (stdlib urllib).

Turns a detected service banner into a product+version keyword and fetches the
matching CVEs (id, CVSS severity/score, published date, summary). Results are
cached in-process to respect NVD rate limits (5 req / 30s anonymous, 50 with an
NVD_API_KEY). No third-party dependency.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE: dict = {}
_CACHE_TTL = 3600

_PRODUCTS = (r"nginx|apache|lighttpd|Microsoft-IIS|Werkzeug|gunicorn|Jetty|Tomcat|vsftpd|"
             r"ProFTPD|Pure-FTPd|Postfix|Exim|Dovecot|MySQL|MariaDB|PostgreSQL|Redis|"
             r"MongoDB|OpenSSL|Samba|Squid|HAProxy|Node\.js|PHP")


def api_key() -> str:
    return os.environ.get("NVD_API_KEY", "").strip()


def clean_banner(banner: str) -> str:
    """Turn a service banner into an NVD keyword, e.g.
    'SSH-2.0-OpenSSH_8.4' -> 'OpenSSH 8.4', 'nginx/1.24' -> 'nginx 1.24'."""
    if not banner:
        return ""
    m = re.search(r"OpenSSH[_/ ]?([0-9][\w.]*)", banner, re.I)
    if m:
        return f"OpenSSH {m.group(1)}"
    m = re.search(rf"({_PRODUCTS})[/ ]?([0-9][\w.]*)", banner, re.I)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    m = re.match(r"([A-Za-z][\w.+-]{2,})[/ ]([0-9][\w.]*)", banner.strip())
    if m:
        return f"{m.group(1)} {m.group(2)}"
    return ""


def _cvss(cve: dict):
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {}) or {}
            sev = arr[0].get("baseSeverity") or d.get("baseSeverity") or ""
            return sev, d.get("baseScore")
    return "", None


def search(keyword: str, limit: int = 5, key: Optional[str] = None, timeout: int = 15) -> List[dict]:
    keyword = (keyword or "").strip()
    if not keyword:
        return []
    now = time.time()
    hit = _CACHE.get(keyword)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    key = key or api_key()
    url = API + "?" + urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": str(limit)})
    headers = {"User-Agent": "netrecon"}
    if key:
        headers["apiKey"] = key
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        return [{"error": f"NVD HTTP {e.code} (rate limit? set NVD_API_KEY)"}]
    except Exception as e:
        return [{"error": f"NVD: {e}"}]
    out = []
    for item in data.get("vulnerabilities", [])[:limit]:
        c = item.get("cve", {}) or {}
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        sev, score = _cvss(c)
        out.append({"id": c.get("id", ""), "severity": sev, "score": score,
                    "published": (c.get("published", "") or "")[:10], "desc": desc[:240]})
    _CACHE[keyword] = (now, out)
    return out


def context_block(hosts: List[dict], key: Optional[str] = None, max_services: int = 6) -> str:
    """Build a live-CVE context block from the distinct service banners in hosts."""
    seen, keywords = set(), []
    for h in hosts:
        pmap = ((h.get("meta", {}) or {}).get("values", {}) or {}).get("ports", {}) or {}
        for v in pmap.values():
            kw = clean_banner(v.get("banner", ""))
            if kw and kw not in seen:
                seen.add(kw)
                keywords.append(kw)
    if not keywords:
        return ""
    lines = []
    for kw in keywords[:max_services]:
        res = search(kw, limit=4, key=key)
        if not res or res[0].get("error"):
            continue
        lines.append(f"{kw}:")
        for c in res:
            lines.append(f"  {c['id']} [{c['severity'] or '?'} {c['score'] if c['score'] is not None else ''}] "
                         f"{c['published']} - {c['desc']}")
    return "\n".join(lines)

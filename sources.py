"""Step 0: structured public feeds. No LLM needed; these already contain the facts.

CISA KEV (exploited CVEs + required action), Have I Been Pwned (breach list),
ransomware.live (victims by country). Indian victims get a passive hosting lookup.
"""
import re
import socket
from datetime import datetime, timedelta, timezone

import httpx

from db import connect

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; threat-ledger-research)"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
RW_URL = "https://api.ransomware.live/v2/victims/{y}/{m:02d}"
RIPE = "https://stat.ripe.net/data/{call}/data.json"

CDN_HINTS = ("cloudflare", "akamai", "fastly", "incapsula", "imperva", "sucuri", "stackpath", "cloudfront")
COUNTRY = {"IN": "India", "US": "United States", "GB": "United Kingdom", "DE": "Germany", "SG": "Singapore"}


def _get(url, **kw):
    r = httpx.get(url, headers=HEADERS, timeout=30, follow_redirects=True, **kw)
    r.raise_for_status()
    return r.json()


def _strip(html: str, n: int = 300) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html or "")).strip()[:n]


def _save(conn, rec: dict) -> int:
    cur = conn.execute(
        "INSERT OR IGNORE INTO articles(url,title,source,published,rss_summary,extracted,fetched_ok) VALUES (?,?,?,?,?,1,1)",
        (rec["url"], rec["title"], rec["source"], rec["published"], rec.get("snippet", "")),
    )
    if not cur.rowcount:
        return 0
    aid = cur.lastrowid
    conn.execute(
        """INSERT INTO incidents(article_id,is_incident,india_relevant,india_reason,incident_title,attack_type,
           victim_org,victim_country,victim_sector,data_hosting_location,foreign_hosted_india_company,cves,
           fix_mitigation,consequences,supporting_snippet) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (aid, 1, int(rec.get("india", False)), rec.get("india_reason", ""), rec["title"], rec["type"],
         rec.get("org"), rec.get("country"), rec.get("sector"), rec.get("hosting"),
         int(rec.get("foreign", False)), ",".join(rec.get("cves", [])), rec.get("fix", ""),
         rec.get("impact", ""), rec.get("snippet", "")),
    )
    return 1


def _recent(date_str: str, days: int) -> bool:
    try:
        d = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return False
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d >= datetime.now(timezone.utc) - timedelta(days=days)


def ingest_kev(conn, days=30) -> int:
    n = 0
    for v in _get(KEV_URL)["vulnerabilities"]:
        if not _recent(v["dateAdded"], days):
            continue
        ransom = " Known to be used in ransomware campaigns." if v.get("knownRansomwareCampaignUse") == "Known" else ""
        n += _save(conn, {
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            "title": f"{v['vendorProject']} {v['product']}: {v['vulnerabilityName']} ({v['cveID']})",
            "source": "CISA KEV", "published": v["dateAdded"], "type": "actively exploited vulnerability",
            "org": v["vendorProject"], "cves": [v["cveID"]], "fix": v["requiredAction"],
            "impact": v["shortDescription"] + ransom, "snippet": v["shortDescription"],
        })
    return n


def ingest_hibp(conn, days=30) -> int:
    n = 0
    for b in _get(HIBP_URL):
        if b.get("IsSpamList") or b.get("IsFabricated") or not _recent(b["AddedDate"], days):
            continue
        classes = ", ".join(b.get("DataClasses", [])[:8])
        n += _save(conn, {
            "url": f"https://haveibeenpwned.com/PwnedWebsites#{b['Name']}",
            "title": f"{b['Title']}: {b['PwnCount']:,} accounts exposed",
            "source": "Have I Been Pwned", "published": b["AddedDate"], "type": "data breach",
            "org": b["Title"],
            "fix": "General advice: change the password on this service and anywhere it was reused, turn on 2FA, and watch for phishing.",
            "impact": f"{b['PwnCount']:,} accounts exposed. Data types: {classes}.",
            "snippet": _strip(b.get("Description", "")),
        })
    return n


def hosting_lookup(domain: str):
    """Passive: DNS A record -> RIPEstat ASN + geo. Returns (text, is_foreign_guess)."""
    domain = domain.split("/")[0].strip().lower()
    try:
        ip = socket.gethostbyname(domain)
    except OSError:
        return "Website domain does not resolve (site may be down or removed).", False
    try:
        asn = _get(RIPE.format(call="prefix-overview"), params={"resource": ip})["data"].get("asns", [{}])
        holder = (asn[0].get("holder") if asn else "") or "unknown network"
        geo = _get(RIPE.format(call="maxmind-geo-lite"), params={"resource": ip})["data"]["located_resources"]
        cc = geo[0]["locations"][0]["country"] if geo and geo[0]["locations"] else "?"
    except Exception:
        return f"Website IP {ip}; lookup failed.", False
    if any(h in holder.lower() for h in CDN_HINTS):
        return f"Website sits behind a CDN ({holder}); real server location unknown.", False
    text = f"Website IP resolves to {COUNTRY.get(cc, cc)} ({holder}). Inferred from DNS, not confirmed; the database may be elsewhere."
    return text, cc not in ("IN", "?")


def ingest_ransomware(conn, days=45) -> int:
    now = datetime.now(timezone.utc)
    months = {(now.year, now.month), ((now - timedelta(days=31)).year, (now - timedelta(days=31)).month)}
    n = 0
    for y, m in sorted(months):
        try:
            victims = _get(RW_URL.format(y=y, m=m))
        except httpx.HTTPError as ex:  # a month may not exist yet or be unavailable
            print(f"[sources] ransomware.live {y}-{m:02d}: {ex}")
            continue
        for v in victims:
            if not v.get("country") or "redacted" in (v.get("description") or "").lower():
                continue
            if not _recent(v["attackdate"], days):
                continue
            india = v["country"] == "IN"
            if not india:  # global ransomware is covered by the news feeds; keep this feed India-only
                continue
            hosting, foreign = (hosting_lookup(v["domain"]) if india and v.get("domain") else (None, False))
            n += _save(conn, {
                "url": v["url"], "title": f"{v['victim']} listed by {v['group']} ransomware group",
                "source": "ransomware.live", "published": v["attackdate"], "type": "ransomware",
                "org": v["victim"], "country": COUNTRY.get(v["country"], v["country"]),
                "sector": v.get("activity") if v.get("activity") != "Not Found" else None,
                "india": india, "india_reason": "Victim country is India (ransomware.live)." if india else "",
                "hosting": hosting, "foreign": foreign,
                "fix": "Not stated. Listing on a leak site is an attacker claim; check the company's own statement.",
                "impact": f"Named on the {v['group']} leak site, which means the group claims it stole data. " + _strip(v.get("description"), 200),
                "snippet": _strip(v.get("description"), 200),
            })
    return n


def ingest_structured() -> None:
    conn = connect()
    for name, fn in (("KEV", ingest_kev), ("HIBP", ingest_hibp), ("ransomware.live", ingest_ransomware)):
        try:
            print(f"[sources] {name}: {fn(conn)} new")
            conn.commit()
        except Exception as ex:  # one dead feed must not stop the others
            print(f"[sources] {name} ERR: {ex}")

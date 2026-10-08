"""Find other outlets covering the same story, so nothing is missed.

Two sources, no LLM:
  1. our own ingested articles (shared CVE, same named victim, or very similar title text)
  2. Google News RSS search, which aggregates hundreds of outlets (public RSS, light use only)
"""
import math
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus, urlparse

import feedparser

from db import connect

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
STOP = set("""the a an and or of to in on for with by at from as is are was were be been this that these those it its into
over after before new says say said how what why who will can could may might has have had not but about up out more
than their they them his her via using use used target targets targeted attack attacks attackers hackers hacker
security cyber data flaw flaws vulnerability vulnerabilities exploited exploit malware campaign""".split())
GENERIC_ORGS = {"microsoft", "google", "apple", "cisco", "adobe", "oracle", "linux", "apache", "android", "windows",
                "ivanti", "fortinet", "citrix", "vmware", "samsung", "mozilla", "chrome", "wordpress"}
GNEWS = "https://news.google.com/rss/search?q={q}&hl=en-IN&gl=IN&ceid=IN:en"
MAX_PER_ITEM = 10
EXTERNAL_LOOKUPS_PER_RUN = 60
RECHECK_AFTER = timedelta(hours=12)
UA = "Mozilla/5.0 (compatible; threat-ledger-research)"


def _tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9][a-z0-9\-\.]{2,}", (text or "").lower()) if t not in STOP]


def _host(url: str) -> str:
    return urlparse(url).netloc.lower().removeprefix("www.")


def _norm_org(org: str) -> str:
    o = re.sub(r"\b(pvt|private|ltd|limited|inc|llc|corp|corporation|group|the)\b\.?", " ", (org or "").lower())
    return re.sub(r"[^a-z0-9 ]", " ", o).strip()


def _cosine(a: Counter, b: Counter, idf: dict) -> float:
    num = sum(a[t] * b[t] * idf.get(t, 1) ** 2 for t in a.keys() & b.keys())
    da = math.sqrt(sum((c * idf.get(t, 1)) ** 2 for t, c in a.items()))
    db_ = math.sqrt(sum((c * idf.get(t, 1)) ** 2 for t, c in b.items()))
    return num / (da * db_) if da and db_ else 0.0


def _add(conn, aid, url, title, source, published, via):
    conn.execute(
        "INSERT OR IGNORE INTO related(article_id,url,title,source,published,via) VALUES (?,?,?,?,?,?)",
        (aid, url, title, source, published, via),
    )


def internal_matches(conn) -> int:
    arts = conn.execute("SELECT id,url,title,source,published,rss_summary,content_md FROM articles").fetchall()
    inc = {r["article_id"]: r for r in conn.execute(
        "SELECT article_id,victim_org,cves FROM incidents WHERE is_incident=1")}
    docs = {}
    for a in arts:
        text = f"{a['title']} {a['title']} {a['rss_summary'] or ''}"
        docs[a["id"]] = {
            "tf": Counter(_tokens(text)),
            "cves": {c.upper() for c in CVE_RE.findall(f"{a['title']} {a['rss_summary'] or ''} {(a['content_md'] or '')[:4000]}")},
            "low": f"{a['title']} {a['rss_summary'] or ''}".lower(),
        }
    df = Counter(t for d in docs.values() for t in d["tf"])
    n = len(docs)
    idf = {t: math.log((n + 1) / (c + 1)) + 1 for t, c in df.items()}
    added = 0
    for a in arts:
        if a["id"] not in inc:
            continue
        da = docs[a["id"]]
        my_cves = da["cves"] | {c for c in (inc[a["id"]]["cves"] or "").split(",") if c}
        org = _norm_org(inc[a["id"]]["victim_org"] or "")
        org_ok = len(org) >= 5 and org not in GENERIC_ORGS and a["source"] not in ("CISA KEV",)
        for b in arts:
            if b["id"] == a["id"] or b["url"] == a["url"] or (b["source"] == a["source"]):
                continue
            db_ = docs[b["id"]]
            via = None
            if my_cves and my_cves & db_["cves"]:
                via = "same CVE"
            else:
                cos = _cosine(da["tf"], db_["tf"], idf)
                if org_ok and org in db_["low"] and cos >= 0.15:
                    via = "same victim"  # a named victim alone is not enough; the text must also overlap
                elif a["source"] not in ("CISA KEV", "Have I Been Pwned") and cos >= 0.42:
                    via = "similar story"
            if via:
                _add(conn, a["id"], b["url"], b["title"], b["source"], b["published"], via)
                added += 1
    return added


def _query_for(title: str, cves: str, org: str, source: str) -> str:
    cve = next((c for c in (cves or "").split(",") if c), "")
    if cve:
        return cve
    if source == "ransomware.live" and org:
        return f'"{org}" ransomware'
    if source == "Have I Been Pwned" and org:
        return f'"{org}" data breach'
    words = [w for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9\-\.]+", title) if w.lower() not in STOP]
    return " ".join(words[:6])


def external_matches(conn, limit: int = EXTERNAL_LOOKUPS_PER_RUN) -> int:
    now = datetime.now(timezone.utc)
    cutoff = (now - RECHECK_AFTER).strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        """SELECT a.id,a.url,a.title,a.source,i.victim_org,i.cves FROM incidents i
           JOIN articles a ON a.id=i.article_id
           LEFT JOIN related_log l ON l.article_id=a.id
           WHERE i.is_incident=1 AND (l.last_checked IS NULL OR l.last_checked < ?)
           ORDER BY i.india_relevant DESC, a.id DESC LIMIT ?""",
        (cutoff, limit),
    ).fetchall()
    added = 0
    for r in rows:
        q = _query_for(r["title"], r["cves"], r["victim_org"], r["source"])
        if not q:
            continue
        feed = feedparser.parse(GNEWS.format(q=quote_plus(q + " when:14d")), agent=UA)
        if not feed.entries and len(q.split()) > 4 and not q.startswith(("CVE-", '"')):
            q = " ".join(q.split()[:4])  # too specific: retry with fewer words
            time.sleep(1.0)
            feed = feedparser.parse(GNEWS.format(q=quote_plus(q + " when:14d")), agent=UA)
        qtok = set(_tokens(q))
        got = 0
        for e in feed.entries:
            src = (e.get("source") or {}).get("title", "") or _host(e.get("link", ""))
            title = re.sub(r"\s+-\s+" + re.escape(src) + r"$", "", e.get("title", "")).strip()
            if not title or src.lower() == (r["source"] or "").lower() or _host(e.get("link", "")) == _host(r["url"]):
                continue
            # keep only results that actually share words with the query (CVE ids always count)
            if not (r["cves"] and q in title) and len(qtok & set(_tokens(title))) < min(2, len(qtok)):
                continue
            _add(conn, r["id"], e["link"], title, src, e.get("published", ""), "news search")
            got += 1
            added += 1
            if got >= MAX_PER_ITEM:
                break
        conn.execute("INSERT OR REPLACE INTO related_log(article_id,last_checked) VALUES (?,datetime('now'))", (r["id"],))
        conn.commit()
        time.sleep(1.0)  # be polite to the news search endpoint
    return added


def find_related() -> None:
    conn = connect()
    print(f"[related] internal: {internal_matches(conn)}")
    conn.commit()
    try:
        print(f"[related] news search: {external_matches(conn)}")
    except Exception as ex:  # never fail the run over this
        print(f"[related] news search ERR: {ex}")
    conn.commit()

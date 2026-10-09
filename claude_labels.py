"""Claude-labeled extraction, used by a scheduled cloud agent while credits last.

  python claude_labels.py export --limit 20      print a batch of pending articles, numbered sentences
  python claude_labels.py finalize labels/X.jsonl resolve sentence numbers to verbatim text -> labels/X.final.jsonl
  python claude_labels.py apply                  load every *.final.jsonl not yet applied into the database

The agent only writes small JSON lines (ids, labels, sentence NUMBERS). Text is always copied
from the article by this script, so the labels cannot contain invented sentences.
"""
import glob
import json
import os
import re
import sys

from db import connect
import extract as E

LABEL_DIR = "labels"
STRUCTURED = ("CISA KEV", "Have I Been Pwned", "ransomware.live")


def article_sentences(title, text):
    tl = title.lower().strip(" .")
    sents = [x for x in E.split_sentences(text or "") if x.lower().strip(" .") != tl]
    return sents or [title]


def pending(conn, limit):
    """Pending news articles, India-looking ones first, then round-robin across sources."""
    conn.execute("CREATE TABLE IF NOT EXISTS claude_labeled (article_id INTEGER PRIMARY KEY)")
    # Newest first. Skip articles Claude already labeled, and rows from the strong-model path
    # (their incident_title differs from the headline); keep unprocessed and small-model rows.
    rows = conn.execute(
        """SELECT a.id,a.source,a.title,a.url,a.rss_summary,a.content_md FROM articles a
           LEFT JOIN incidents i ON i.article_id=a.id
           LEFT JOIN claude_labeled c ON c.article_id=a.id
           WHERE c.article_id IS NULL AND a.source NOT IN ('CISA KEV','Have I Been Pwned','ransomware.live')
             AND (a.content_md IS NOT NULL OR length(a.rss_summary)>40)
             AND (i.id IS NULL OR i.incident_title = a.title)
           ORDER BY a.id DESC"""
    ).fetchall()
    india = [r for r in rows if E.INDIA_RE.search(f"{r['title']} {r['rss_summary'] or ''}")]
    rest, by = [], {}
    for r in rows:
        if r not in india:
            by.setdefault(r["source"], []).append(r)
    while any(by.values()):
        for s in list(by):
            if by[s]:
                rest.append(by[s].pop(0))
    return (india + rest)[:limit]


def cmd_export(limit):
    conn = connect()
    batch = pending(conn, limit)
    print(f"# {len(batch)} articles to label\n")
    for r in batch:
        sents = article_sentences(r["title"], r["content_md"] or r["rss_summary"])[:25]
        print(f"### id={r['id']} | {r['source']} | {r['title']}")
        for i, s in enumerate(sents, 1):
            print(f"{i}. {s[:200]}")
        print()


def cmd_finalize(path):
    conn = connect()
    out_path = re.sub(r"\.jsonl$", "", path) + ".final.jsonl"
    kept = bad = 0
    with open(path, encoding="utf-8") as f, open(out_path, "w", encoding="utf-8") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                a = conn.execute("SELECT title,rss_summary,content_md FROM articles WHERE id=?", (int(row["id"]),)).fetchone()
            except (ValueError, KeyError, json.JSONDecodeError):
                bad += 1
                continue
            if not a:
                bad += 1
                continue
            sents = article_sentences(a["title"], a["content_md"] or a["rss_summary"])[:40]

            def pick(key):
                idx = [i for i in (row.get(key) or []) if isinstance(i, int) and 1 <= i <= len(sents)]
                return " ".join(sents[i - 1] for i in dict.fromkeys(idx))

            blob = f"{a['title']} {' '.join(sents)}"
            hits = sorted({m.group(0).lower() for m in E.INDIA_RE.finditer(blob)})
            impact = pick("impact")
            out.write(json.dumps({
                "id": int(row["id"]), "inc": int(bool(row.get("inc"))),
                "india": int(bool(row.get("india")) and bool(hits)), "india_hits": hits[:4],
                "attack_type": (row.get("attack_type") or "")[:60].lower(),
                "victim_org": row.get("victim_org"), "victim_country": row.get("victim_country"),
                "victim_sector": row.get("victim_sector"),
                "fix": pick("fix"), "impact": impact, "quote": impact.split(". ")[0] if impact else sents[0],
                "cves": sorted({c.upper() for c in E.CVE_RE.findall(blob)}),
            }, ensure_ascii=False) + "\n")
            kept += 1
    print(f"[finalize] {kept} rows -> {out_path} ({bad} bad lines skipped)")


def apply_all(conn=None):
    conn = conn or connect()
    conn.execute("CREATE TABLE IF NOT EXISTS labels_applied (file TEXT PRIMARY KEY)")
    done = {r[0] for r in conn.execute("SELECT file FROM labels_applied")}
    total = 0
    for path in sorted(glob.glob(os.path.join(LABEL_DIR, "*.final.jsonl"))):
        name = os.path.basename(path)
        if name in done:
            continue
        n = 0
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line)
            a = conn.execute("SELECT title FROM articles WHERE id=?", (r["id"],)).fetchone()
            if not a:
                continue
            reason = f"Text mentions: {', '.join(r['india_hits'])}." if r["india"] else ""
            conn.execute(
                """INSERT OR REPLACE INTO incidents(article_id,is_incident,india_relevant,india_reason,incident_title,
                   incident_date,attack_type,victim_org,victim_country,victim_sector,data_hosting_location,
                   foreign_hosted_india_company,cves,fix_mitigation,consequences,supporting_snippet)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (r["id"], r["inc"], r["india"], reason, a["title"], None, r["attack_type"], r["victim_org"],
                 r["victim_country"], r["victim_sector"], None, 0, ",".join(r["cves"]), r["fix"], r["impact"], r["quote"]),
            )
            conn.execute("UPDATE articles SET extracted=1 WHERE id=?", (r["id"],))
            conn.execute("CREATE TABLE IF NOT EXISTS claude_labeled (article_id INTEGER PRIMARY KEY)")
            conn.execute("INSERT OR IGNORE INTO claude_labeled(article_id) VALUES (?)", (r["id"],))
            n += 1
        conn.execute("INSERT INTO labels_applied(file) VALUES (?)", (name,))
        conn.commit()
        total += n
        print(f"[labels] applied {n} rows from {name}")
    return total


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "export":
        cmd_export(int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else 20)
    elif cmd == "finalize":
        cmd_finalize(sys.argv[2])
    elif cmd == "apply":
        apply_all()
    else:
        raise SystemExit(__doc__)

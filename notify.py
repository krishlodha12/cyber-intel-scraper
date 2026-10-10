"""Push alerts for NEW India-related incidents, via ntfy.sh (free, no account).

The topic name is the only secret: it lives in the NTFY_TOPIC GitHub secret, never in the repo.
The first run only records what is already on the site (a baseline) so you are not flooded.
"""
import os
import sys

import httpx

from db import connect

SITE = "https://krishlodha12.github.io/cyber-intel-scraper/"
MAX_INDIVIDUAL = 5


def build(row) -> dict:
    bits = [row["source"]]
    if row["attack_type"]:
        bits.append(row["attack_type"])
    if row["foreign_hosted_india_company"]:
        bits.append("website likely hosted abroad")
    detail = " · ".join(bits)
    impact = (row["consequences"] or "").strip()
    message = detail + (": " + impact[:200] if impact else "")
    return {"title": row["title"][:100], "message": message[:300], "click": row["url"],
            "tags": ["flag-in", "warning"], "priority": 3}


def send(topic: str, payload: dict) -> bool:
    try:
        r = httpx.post("https://ntfy.sh/", json={"topic": topic, **payload}, timeout=20)
        return r.status_code == 200
    except httpx.HTTPError as ex:
        print(f"[notify] send failed: {ex}")
        return False


def main() -> None:
    topic = os.getenv("NTFY_TOPIC", "").strip()
    conn = connect()
    conn.execute("CREATE TABLE IF NOT EXISTS notified (article_id INTEGER PRIMARY KEY)")
    rows = conn.execute(
        """SELECT a.id,a.title,a.url,a.source,i.attack_type,i.consequences,i.foreign_hosted_india_company
           FROM incidents i JOIN articles a ON a.id=i.article_id
           WHERE i.is_incident=1 AND i.india_relevant=1
             AND a.id NOT IN (SELECT article_id FROM notified) ORDER BY a.id"""
    ).fetchall()
    first_run = conn.execute("SELECT COUNT(*) FROM notified").fetchone()[0] == 0

    if not topic:
        print("[notify] no NTFY_TOPIC secret set; alerts are off")
        return
    if first_run:
        conn.executemany("INSERT OR IGNORE INTO notified(article_id) VALUES (?)", [(r["id"],) for r in rows])
        conn.commit()
        print(f"[notify] baseline: marked {len(rows)} existing India incidents as seen, no alerts sent")
        return
    if not rows:
        print("[notify] nothing new")
        return

    sent = 0
    for r in rows[:MAX_INDIVIDUAL]:
        if send(topic, build(r)):
            conn.execute("INSERT OR IGNORE INTO notified(article_id) VALUES (?)", (r["id"],))
            sent += 1
    rest = rows[MAX_INDIVIDUAL:]
    if rest and send(topic, {"title": f"{len(rest)} more India incidents", "message": "Open Threat Ledger to read them.",
                             "click": SITE, "tags": ["flag-in"], "priority": 2}):
        conn.executemany("INSERT OR IGNORE INTO notified(article_id) VALUES (?)", [(r["id"],) for r in rest])
        sent += len(rest)
    conn.commit()
    print(f"[notify] alerted on {sent} of {len(rows)} new India incidents")


if __name__ == "__main__":
    main()
    sys.exit(0)  # an alert problem must never fail the run

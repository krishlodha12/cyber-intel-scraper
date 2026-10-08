"""Step 4: bake the incidents into a single static page (site/index.html)."""
import json
import os
from datetime import datetime, timezone
from db import connect

SITE_DIR = "site"


def build_site(days: int = 30) -> str:
    conn = connect()
    rows = conn.execute(
        """SELECT a.url,a.title,a.source,a.published,a.created_at,i.*
           FROM incidents i JOIN articles a ON a.id=i.article_id
           WHERE i.is_incident=1 AND a.created_at >= datetime('now', ?)
           ORDER BY a.created_at DESC, a.id DESC""",
        (f"-{days} days",),
    ).fetchall()
    rel = {}
    for r in conn.execute("SELECT article_id,url,title,source,published,via FROM related ORDER BY id"):
        rel.setdefault(r["article_id"], []).append(
            {"url": r["url"], "title": r["title"], "source": r["source"], "published": r["published"], "via": r["via"]})
    items = [
        {
            "title": r["incident_title"] or r["title"],
            "url": r["url"],
            "source": r["source"],
            "published": r["published"],
            "added": r["created_at"],
            "type": r["attack_type"] or "",
            "org": r["victim_org"] or "",
            "country": r["victim_country"] or "",
            "sector": r["victim_sector"] or "",
            "hosting": r["data_hosting_location"] or "",
            "foreign": bool(r["foreign_hosted_india_company"]),
            "india": bool(r["india_relevant"]),
            "india_reason": r["india_reason"] or "",
            "cves": [c for c in (r["cves"] or "").split(",") if c],
            "fix": r["fix_mitigation"] or "",
            "impact": r["consequences"] or "",
            "quote": r["supporting_snippet"] or "",
            "related": rel.get(r["article_id"], []),
        }
        for r in rows
    ]
    payload = {"generated": datetime.now(timezone.utc).isoformat(timespec="minutes"), "items": items}
    blob = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    with open(os.path.join(SITE_DIR, "template.html"), encoding="utf-8") as f:
        html = f.read().replace("__DATA__", blob)
    out = os.path.join(SITE_DIR, "index.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[site] {len(items)} incidents -> {out}")
    return out

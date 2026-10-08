"""Step 3: markdown digest."""
from datetime import date
from db import connect


def _section(rows, heading):
    out = [f"## {heading} ({len(rows)})\n"]
    for r in rows:
        flag = " ⚠️ foreign-hosted Indian company" if r["foreign_hosted_india_company"] else ""
        out.append(f"### [{r['incident_title'] or r['title']}]({r['url']}){flag}")
        out.append(f"*{r['source']} · {r['published']}* · **{r['attack_type']}** · {r['victim_org'] or 'n/a'} ({r['victim_country'] or '?'})\n")
        if r["data_hosting_location"]:
            out.append(f"- **Hosting (as stated):** {r['data_hosting_location']}")
        if r["cves"]:
            out.append(f"- **CVEs:** {r['cves']}")
        out.append(f"- **Fix:** {r['fix_mitigation'] or 'not stated'}")
        out.append(f"- **Consequences:** {r['consequences'] or 'not stated'}")
        if r["supporting_snippet"]:
            out.append(f"- > {r['supporting_snippet']}")
        out.append("")
    return "\n".join(out)


def write_digest(days: int = 7) -> str:
    conn = connect()
    q = """SELECT a.url,a.title,a.source,a.published,i.* FROM incidents i JOIN articles a ON a.id=i.article_id
           WHERE i.is_incident=1 AND a.created_at >= datetime('now', ?) ORDER BY a.created_at DESC"""
    rows = conn.execute(q, (f"-{days} days",)).fetchall()
    india = [r for r in rows if r["india_relevant"]]
    world = [r for r in rows if not r["india_relevant"]]
    md = f"# Cyber intel digest {date.today()}\n\n" + _section(india, "India") + "\n" + _section(world, "Global")
    path = f"digest_{date.today()}.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[digest] wrote {path}")
    return path

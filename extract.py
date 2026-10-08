"""Step 2: structured extraction + India filter via OpenRouter."""
import json
from typing import Optional
from openai import OpenAI
from pydantic import BaseModel, Field
from config import LLM_BASE_URL, OPENROUTER_API_KEY, OPENROUTER_MODEL, PER_SOURCE_PER_RUN
from db import connect


class Incident(BaseModel):
    is_incident: bool = Field(description="True only if the article reports a concrete cyber incident, vulnerability, scam campaign, or new security tool/advisory. False for opinion, ads, unrelated news.")
    india_relevant: bool = Field(description="True if victims, attackers, regulators, or affected users are in India, or it concerns Indian law (DPDP, CERT-In, RBI), UPI, Aadhaar, etc.")
    india_reason: str = Field(default="", description="One short sentence on why it is or isn't India-relevant.")
    incident_title: str = ""
    incident_date: Optional[str] = Field(default=None, description="YYYY-MM-DD if stated, else null")
    attack_type: str = Field(default="", description="e.g. ransomware, data leak, phishing, UPI fraud, zero-day, supply chain, new tool")
    victim_org: Optional[str] = None
    victim_country: Optional[str] = None
    victim_sector: Optional[str] = None
    data_hosting_location: Optional[str] = Field(default=None, description="Where the data/database was hosted ONLY if the article states it (e.g. 'AWS US-East', 'Singapore'). Never guess.")
    foreign_hosted_india_company: bool = Field(default=False, description="True only if the article explicitly says an Indian company's data/database was hosted outside India.")
    cves: list[str] = Field(default_factory=list)
    fix_mitigation: str = Field(default="", description="Patches, config changes, or user actions recommended in the article.")
    consequences: str = Field(default="", description="Stated impact: data stolen, downtime, fines, financial loss, etc.")
    supporting_snippet: str = Field(default="", description="One verbatim sentence from the article supporting the main claim, for human verification.")


SYSTEM = (
    "You extract structured cybersecurity intelligence from news articles. "
    "Use ONLY facts stated in the article; use null/empty when unknown. Never infer hosting location. "
    "Reply with a single JSON object matching this schema:\n"
    + json.dumps(Incident.model_json_schema())
)


def _client() -> OpenAI:
    if not OPENROUTER_API_KEY:
        raise SystemExit("Set LLM_API_KEY (or OPENROUTER_API_KEY) in .env.")
    return OpenAI(base_url=LLM_BASE_URL, api_key=OPENROUTER_API_KEY)


def extract_pending(limit: int = 200) -> None:
    client = _client()
    conn = connect()
    rows = conn.execute(
        """SELECT id,url,title,source,rss_summary,content_md FROM (
               SELECT *, ROW_NUMBER() OVER (PARTITION BY source ORDER BY id) AS rn FROM articles
               WHERE extracted=0 AND (content_md IS NOT NULL OR rss_summary != ''))
           WHERE rn <= ? ORDER BY rn, id LIMIT ?""",
        (PER_SOURCE_PER_RUN, limit),
    ).fetchall()
    for r in rows:
        text = r["content_md"] or r["rss_summary"]
        try:
            resp = client.chat.completions.create(
                model=OPENROUTER_MODEL,
                temperature=0,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": f"Source: {r['source']}\nTitle: {r['title']}\nURL: {r['url']}\n\n{text}"},
                ],
            )
            inc = Incident.model_validate_json(resp.choices[0].message.content)
        except Exception as ex:
            print(f"[extract] ERR {r['url']}: {ex}")
            continue
        conn.execute(
            """INSERT OR REPLACE INTO incidents(article_id,is_incident,india_relevant,india_reason,incident_title,
               incident_date,attack_type,victim_org,victim_country,victim_sector,data_hosting_location,
               foreign_hosted_india_company,cves,fix_mitigation,consequences,supporting_snippet)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (r["id"], inc.is_incident, inc.india_relevant, inc.india_reason, inc.incident_title, inc.incident_date,
             inc.attack_type, inc.victim_org, inc.victim_country, inc.victim_sector, inc.data_hosting_location,
             inc.foreign_hosted_india_company, ",".join(inc.cves), inc.fix_mitigation, inc.consequences,
             inc.supporting_snippet),
        )
        conn.execute("UPDATE articles SET extracted=1 WHERE id=?", (r["id"],))
        conn.commit()
        print(f"[extract] {'IN ' if inc.india_relevant else '   '} {inc.attack_type or '-':<14} {r['title'][:70]}")

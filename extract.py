"""Step 2: structured extraction + India filter.

Two modes (EXTRACT_MODE):
  full     the model writes every field (needs a strong model, e.g. via OpenRouter/OmniRoute)
  pointer  the model only PICKS sentence numbers and short labels; fix/impact text is copied
           verbatim from the article. Small free models can do this, and cannot invent facts.
"""
import json
import os
import re
from typing import Optional
from openai import OpenAI
from pydantic import BaseModel, Field, ValidationError, field_validator
from config import LLM_BASE_URL, OPENROUTER_API_KEY, OPENROUTER_MODEL, PER_SOURCE_PER_RUN
from db import connect

EXTRACT_MODE = os.getenv("EXTRACT_MODE", "full")
EXTRACT_LIMIT = int(os.getenv("EXTRACT_LIMIT", "200"))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# India evidence must literally appear in the text; the model alone cannot mark something India-relevant.
INDIA_RE = re.compile(
    r"\b(india|indian|upi|aadhaar|aadhar|rbi|cert-in|dpdp|npci|sebi|meity|mumbai|delhi|bengaluru|bangalore|"
    r"hyderabad|chennai|kolkata|pune|gurugram|noida|crore|lakh)\b|₹",
    re.I,
)


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


FIX_RE = re.compile(
    r"\b(patch|patched|update|updated|upgrade|upgrading|mitigat\w*|disable|disabled|apply|applying|recommend\w*|advis\w*|"
    r"should|urge\w*|block\w*|rotate|reset|install\w*|workaround|fix|fixed|fixes|remediat\w*|secure|enable|restrict\w*|"
    r"revoke|isolate)\b", re.I)
IMPACT_RE = re.compile(
    r"\b(stole\w*|stolen|exposed|leak\w*|records?|million|billion|thousands?|affected|victims?|encrypt\w*|ransom\w*|"
    r"downtime|outage|loss|losses|lost|compromis\w*|breach\w*|exfiltrat\w*|hijack\w*|disrupt\w*|damage|fined?|"
    r"accounts?|customers?|users?|servers?|devices?|organi[sz]ations?)\b", re.I)
INCIDENT_RE = re.compile(
    r"\b(attack\w*|breach\w*|hack\w*|ransomware|malware|vulnerab\w*|exploit\w*|zero-day|phishing|scam|fraud|leak\w*|"
    r"stolen|backdoor|botnet|cve-\d{4}|patch\w*|compromis\w*|extortion|espionage|stealer|spyware|worm|ddos|advisory)\b",
    re.I)


class Pointer(BaseModel):
    """Tolerant of sloppy small-model output: wrong types are coerced or dropped instead of failing the article."""
    is_incident: bool = False
    india_relevant: bool = False
    attack_type: str = ""
    victim_org: Optional[str] = None
    victim_country: Optional[str] = None
    victim_sector: Optional[str] = None
    fix_sentences: list[int] = Field(default_factory=list)
    impact_sentences: list[int] = Field(default_factory=list)

    @field_validator("is_incident", "india_relevant", mode="before")
    @classmethod
    def _bool(cls, v):
        if isinstance(v, str):
            return v.strip().lower() in ("true", "yes", "1")
        return bool(v)

    @field_validator("attack_type", "victim_org", "victim_country", "victim_sector", mode="before")
    @classmethod
    def _text(cls, v):
        if v is None:
            return None
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v if x)
        v = str(v).strip()
        return v if v and v.lower() not in ("null", "none", "n/a", "unknown") else None

    @field_validator("attack_type", mode="after")
    @classmethod
    def _at(cls, v):
        return v or ""

    @field_validator("fix_sentences", "impact_sentences", mode="before")
    @classmethod
    def _ints(cls, v):
        if isinstance(v, (int, str)):
            v = [v]
        out = []
        for x in v or []:
            try:
                out.append(int(str(x).strip().rstrip(".")))
            except ValueError:
                pass
        return out


SYSTEM = (
    "You extract structured cybersecurity intelligence from news articles. "
    "Use ONLY facts stated in the article; use null/empty when unknown. Never infer hosting location. "
    "Reply with a single JSON object matching this schema:\n"
    + json.dumps(Incident.model_json_schema())
)

SYSTEM_POINTER = (
    "You label cybersecurity news. The article is split into numbered sentences. Reply with ONE JSON object:\n"
    '{"is_incident": bool, "india_relevant": bool, "attack_type": str, "victim_org": str|null, '
    '"victim_country": str|null, "victim_sector": str|null, "fix_sentences": [int], "impact_sentences": [int]}\n'
    "is_incident: true only if it reports a concrete attack, breach, vulnerability, scam campaign or security advisory "
    "(false for opinion, ads, product news, policy talk).\n"
    "india_relevant: true only if the victims, attackers, regulators or users involved are in India.\n"
    "attack_type: 1-3 words such as ransomware, data breach, phishing, zero-day, malware, scam.\n"
    "fix_sentences: numbers of sentences that tell readers what to do or what was patched (empty list if none).\n"
    "impact_sentences: numbers of sentences that state the damage (data stolen, downtime, money lost).\n"
    "Output sentence NUMBERS only, never text. Use null or [] when unsure."
)


def _client() -> OpenAI:
    if not OPENROUTER_API_KEY:
        raise SystemExit("Set LLM_API_KEY (or OPENROUTER_API_KEY) in .env.")
    return OpenAI(base_url=LLM_BASE_URL, api_key=OPENROUTER_API_KEY, timeout=180)


def split_sentences(text: str, max_sentences: int = 40, max_chars: int = 5000) -> list[str]:
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", text or "")           # images
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)               # links -> text
    text = re.sub(r"^[#>*\-\s]+", "", text, flags=re.M)               # markdown markers
    out, used = [], 0
    for chunk in re.split(r"\n{2,}", text):
        for s in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'])", re.sub(r"\s+", " ", chunk).strip()):
            if 20 <= len(s) <= 400:
                out.append(s)
                used += len(s)
                if len(out) >= max_sentences or used >= max_chars:
                    return out
    return out


def _pick(sents: list[str], idx: list[int], must: "re.Pattern", keep: int = 3) -> str:
    """Copy the chosen sentences verbatim, but only those that pass a keyword check (guards against a weak model)."""
    seen, picked = set(), []
    for i in idx:
        if 1 <= i <= len(sents) and i not in seen and must.search(sents[i - 1]):
            seen.add(i)
            picked.append(sents[i - 1])
        if len(picked) >= keep:
            break
    return " ".join(picked)


def _run_full(client, r, text):
    resp = client.chat.completions.create(
        model=OPENROUTER_MODEL, temperature=0, response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Source: {r['source']}\nTitle: {r['title']}\nURL: {r['url']}\n\n{text}"},
        ],
    )
    inc = Incident.model_validate_json(resp.choices[0].message.content)
    return inc, [inc.is_incident, inc.india_relevant, inc.india_reason, inc.incident_title, inc.incident_date,
                 inc.attack_type, inc.victim_org, inc.victim_country, inc.victim_sector, inc.data_hosting_location,
                 inc.foreign_hosted_india_company, ",".join(inc.cves), inc.fix_mitigation, inc.consequences,
                 inc.supporting_snippet]


def _run_pointer(client, r, text):
    sents = split_sentences(text)
    if not sents:
        # RSS-only articles can be a single short line: classify from the title alone
        sents = [r["title"]]
    numbered = "\n".join(f"{i}. {s}" for i, s in enumerate(sents, 1))
    p = None
    for attempt in range(2):  # small models sometimes break the JSON; retry once
        resp = client.chat.completions.create(
            model=OPENROUTER_MODEL, temperature=0, response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_POINTER},
                {"role": "user", "content": f"Title: {r['title']}\n\n{numbered}"
                 + ("\n\nReply with the JSON object only." if attempt else "")},
            ],
        )
        raw = (resp.choices[0].message.content or "").strip()
        if not raw:
            raise RuntimeError("empty model reply")  # transient: leave the article for the next run
        m = re.search(r"\{.*\}", raw, re.S)
        try:
            p = Pointer.model_validate_json(m.group(0) if m else raw)
            break
        except ValidationError:
            if attempt:
                raise
    blob = f"{r['title']} {' '.join(sents)}"
    hits = sorted({m.group(0).lower() for m in INDIA_RE.finditer(blob)})
    india = bool(p.india_relevant and hits)
    reason = f"Text mentions: {', '.join(hits[:4])}." if india else ""
    impact = _pick(sents, [i for i in p.impact_sentences if i not in p.fix_sentences], IMPACT_RE)
    is_inc = bool(p.is_incident and INCIDENT_RE.search(blob))  # an incident must read like one
    row = [is_inc, india, reason, r["title"], None, p.attack_type.strip().lower()[:60], p.victim_org,
           p.victim_country, p.victim_sector, None, False, ",".join(sorted({c.upper() for c in CVE_RE.findall(blob)})),
           _pick(sents, p.fix_sentences, FIX_RE), impact, impact.split(". ")[0] if impact else sents[0]]
    return p, row


def extract_pending(limit: int = EXTRACT_LIMIT) -> None:
    client = _client()
    conn = connect()
    run = _run_pointer if EXTRACT_MODE == "pointer" else _run_full
    rows = conn.execute(
        """SELECT id,url,title,source,rss_summary,content_md FROM (
               SELECT *, ROW_NUMBER() OVER (PARTITION BY source ORDER BY id) AS rn FROM articles
               WHERE extracted=0 AND (content_md IS NOT NULL OR rss_summary != ''))
           WHERE rn <= ? ORDER BY rn, id LIMIT ?""",
        (PER_SOURCE_PER_RUN, limit),
    ).fetchall()
    print(f"[extract] mode={EXTRACT_MODE} model={OPENROUTER_MODEL} articles={len(rows)}")
    for r in rows:
        text = r["content_md"] or r["rss_summary"]
        try:
            _, values = run(client, r, text)
        except (ValidationError, ValueError, json.JSONDecodeError) as ex:
            print(f"[extract] SKIP {r['url']}: {str(ex)[:80]}")
            conn.execute("UPDATE articles SET extracted=1 WHERE id=?", (r["id"],))  # bad output: do not retry forever
            conn.commit()
            continue
        except Exception as ex:  # network/server problem: leave it for the next run
            print(f"[extract] ERR {r['url']}: {ex}")
            continue
        conn.execute(
            """INSERT OR REPLACE INTO incidents(article_id,is_incident,india_relevant,india_reason,incident_title,
               incident_date,attack_type,victim_org,victim_country,victim_sector,data_hosting_location,
               foreign_hosted_india_company,cves,fix_mitigation,consequences,supporting_snippet)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (r["id"], *values),
        )
        conn.execute("UPDATE articles SET extracted=1 WHERE id=?", (r["id"],))
        conn.commit()
        print(f"[extract] {'IN ' if values[1] else '   '} {values[5] or '-':<14} {r['title'][:70]}")

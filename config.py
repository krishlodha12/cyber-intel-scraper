import os
from dotenv import load_dotenv

load_dotenv()

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")  # e.g. http://localhost:20128/v1 for OmniRoute
OPENROUTER_API_KEY = os.getenv("LLM_API_KEY") or os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.5-flash")
DB_PATH = os.getenv("DB_PATH", "intel.db")

# (name, region, rss_url). region is only a hint; the LLM decides India relevance.
FEEDS = [
    ("BleepingComputer", "global", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "global", "https://feeds.feedburner.com/TheHackersNews"),
    ("Krebs on Security", "global", "https://krebsonsecurity.com/feed/"),
    ("Dark Reading", "global", "https://www.darkreading.com/rss.xml"),
    ("CISA Advisories", "global", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("DataBreaches.net", "global", "https://databreaches.net/feed/"),
    ("SecurityWeek", "global", "https://www.securityweek.com/feed/"),
    ("The Record", "global", "https://therecord.media/feed"),
    ("Infosecurity Magazine", "global", "https://www.infosecurity-magazine.com/rss/news/"),
    ("HackRead", "global", "https://hackread.com/feed/"),
    ("Security Affairs", "global", "https://securityaffairs.com/feed"),
    ("Help Net Security", "global", "https://www.helpnetsecurity.com/feed/"),
    ("The Register Security", "global", "https://www.theregister.com/security/headlines.atom"),
    ("Ars Technica Security", "global", "https://arstechnica.com/security/feed/"),
    ("TechCrunch Security", "global", "https://techcrunch.com/category/security/feed/"),
    ("Cisco Talos", "global", "https://blog.talosintelligence.com/rss/"),
    ("Microsoft Security", "global", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("The Cyber Express", "india", "https://thecyberexpress.com/feed/"),
    ("Cyble", "india", "https://cyble.com/feed/"),
    ("Seqrite", "india", "https://www.seqrite.com/blog/feed/"),
    ("Medianama", "india", "https://www.medianama.com/feed/"),
    ("Inc42", "india", "https://inc42.com/feed/"),
    ("The Hindu Tech", "india", "https://www.thehindu.com/sci-tech/technology/feeder/default.rss"),
    ("Indian Express Tech", "india", "https://indianexpress.com/section/technology/feed/"),
    ("ET Tech", "india", "https://economictimes.indiatimes.com/tech/rssfeeds/13357270.cms"),
]

# Cheap pre-filter for generic-news feeds (Medianama, ET) so we don't pay the LLM for unrelated articles.
SECURITY_KEYWORDS = (
    "breach", "hack", "ransomware", "malware", "phishing", "vulnerab", "cve-", "leak",
    "cyber", "scam", "fraud", "exploit", "data protection", "dpdp", "cert-in", "upi",
    "security", "attack", "stolen", "exposed",
)
GENERIC_FEEDS = {"Medianama", "ET Tech", "Inc42", "The Hindu Tech", "Indian Express Tech"}

PER_SOURCE_PER_RUN = 6  # fetch/extract at most this many new articles per source per run, so no source starves the rest

REQUEST_DELAY_S = 2.0  # politeness delay between article fetches
MAX_ARTICLE_CHARS = 12000

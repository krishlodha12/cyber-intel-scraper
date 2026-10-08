import sqlite3
from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    title TEXT,
    source TEXT,
    published TEXT,
    rss_summary TEXT,
    content_md TEXT,
    fetched_ok INTEGER DEFAULT 0,
    extracted INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    article_id INTEGER UNIQUE REFERENCES articles(id),
    is_incident INTEGER,
    india_relevant INTEGER,
    india_reason TEXT,
    incident_title TEXT,
    incident_date TEXT,
    attack_type TEXT,
    victim_org TEXT,
    victim_country TEXT,
    victim_sector TEXT,
    data_hosting_location TEXT,
    foreign_hosted_india_company INTEGER,
    cves TEXT,
    fix_mitigation TEXT,
    consequences TEXT,
    supporting_snippet TEXT
);
CREATE TABLE IF NOT EXISTS related (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    url TEXT NOT NULL,
    title TEXT,
    source TEXT,
    published TEXT,
    via TEXT,
    UNIQUE(article_id, url)
);
CREATE TABLE IF NOT EXISTS related_log (
    article_id INTEGER PRIMARY KEY,
    last_checked TEXT
);
"""


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn

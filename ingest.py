"""Step 1: pull article URLs from RSS feeds, then fetch full text with Crawl4AI."""
import asyncio
import os
import re
import feedparser
from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode
from config import FEEDS, SECURITY_KEYWORDS, GENERIC_FEEDS, REQUEST_DELAY_S, MAX_ARTICLE_CHARS, PER_SOURCE_PER_RUN
from db import connect


def ingest_feeds() -> int:
    conn = connect()
    new = 0
    for name, _region, url in FEEDS:
        feed = feedparser.parse(url, agent="Mozilla/5.0 (cyber-intel-research)")
        if not feed.entries:
            print(f"[feed] {name}: no entries (blocked or bad URL?)")
            continue
        for e in feed.entries[:25]:
            link = e.get("link")
            title = e.get("title", "")
            summary = re.sub(r"<[^>]+>", " ", e.get("summary", ""))
            if not link:
                continue
            if name in GENERIC_FEEDS and not any(k in (title + summary).lower() for k in SECURITY_KEYWORDS):
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO articles(url,title,source,published,rss_summary) VALUES (?,?,?,?,?)",
                (link, title, name, e.get("published", ""), summary.strip()[:2000]),
            )
            new += cur.rowcount
        print(f"[feed] {name}: {len(feed.entries)} entries")
    conn.commit()
    print(f"[feed] {new} new articles")
    return new


async def fetch_articles(limit: int = int(os.getenv("FETCH_LIMIT", "200"))) -> None:
    conn = connect()
    rows = conn.execute(
        """SELECT id,url FROM (
               SELECT id,url,ROW_NUMBER() OVER (PARTITION BY source ORDER BY id) AS rn
               FROM articles WHERE content_md IS NULL AND fetched_ok=0 AND source NOT IN ('CISA KEV','Have I Been Pwned','ransomware.live'))
           WHERE rn <= ? ORDER BY rn, id LIMIT ?""",
        (PER_SOURCE_PER_RUN, limit),
    ).fetchall()
    if not rows:
        return
    cfg = CrawlerRunConfig(cache_mode=CacheMode.BYPASS, word_count_threshold=30)
    async with AsyncWebCrawler(config=BrowserConfig(headless=True, verbose=False)) as crawler:
        for r in rows:
            try:
                res = await crawler.arun(url=r["url"], config=cfg)
                md = ""
                if res.success and res.markdown:
                    md = getattr(res.markdown, "fit_markdown", None) or res.markdown.raw_markdown
                md = (md or "")[:MAX_ARTICLE_CHARS]
                ok = len(md) > 400
                conn.execute(
                    "UPDATE articles SET content_md=?, fetched_ok=? WHERE id=?",
                    (md if ok else None, 1 if ok else -1, r["id"]),
                )
                print(f"[fetch] {'ok  ' if ok else 'FAIL'} {r['url']}")
            except Exception as ex:  # one bad page must not kill the run
                conn.execute("UPDATE articles SET fetched_ok=-1 WHERE id=?", (r["id"],))
                print(f"[fetch] ERR  {r['url']}: {ex}")
            conn.commit()
            await asyncio.sleep(REQUEST_DELAY_S)

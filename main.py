import asyncio
import sys
from ingest import ingest_feeds, fetch_articles
from extract import extract_pending
from digest import write_digest
from build_site import build_site
from sources import ingest_structured
from related import find_related
from claude_labels import apply_all
from config import OPENROUTER_API_KEY

USAGE = "usage: python main.py [ingest|extract|digest|sources|related|site|all]"


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd not in {"ingest", "extract", "digest", "sources", "related", "labels", "site", "all"}:
        raise SystemExit(USAGE)
    if cmd in {"sources", "all"}:
        ingest_structured()
    if cmd in {"ingest", "all"}:
        ingest_feeds()
        asyncio.run(fetch_articles())
    if cmd in {"labels", "all"}:
        apply_all()  # labels written by the scheduled Claude agent take priority over the small model
    if cmd == "extract" or (cmd == "all" and OPENROUTER_API_KEY):
        extract_pending()
    elif cmd == "all":
        print("[extract] no LLM key configured; skipping (structured feeds still ran)")
    if cmd in {"related", "all"}:
        find_related()
    if cmd in {"digest", "all"}:
        write_digest()
    if cmd in {"site", "all"}:
        build_site()


if __name__ == "__main__":
    main()

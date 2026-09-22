import os
import argparse
import csv
import re
import sys
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Sequence, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
import feedparser
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from pymisp import MISPEvent, PyMISP
from dateutil import parser
from urllib.parse import urljoin, urlparse

from ioc_extract import (
    extract_iocs_from_content,
    create_misp_event_object,
    COMMON_DOMAINS,
    to_yyyy_mm_dd,
)

urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
)
logger = logging.getLogger(__name__)

env_path = Path(__file__).resolve().parent / ".env"
if not env_path.exists():
    env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

MISP_URL = os.getenv("MISP_URL", "https://misp-core")
MISP_KEY = os.getenv("MISP_KEY", "")
if not MISP_KEY and Path("/shared/authkey.txt").exists():
    MISP_KEY = Path("/shared/authkey.txt").read_text().strip()

RSS_FEEDS_CSV = str(Path(__file__).resolve().parent / "config" / "rss_feeds.csv")
OUTPUT_CSV = f"ioc_stats_{datetime.now().strftime('%Y%m%d')}.csv"
STATS_FIELDNAMES = ["date", "vendor", "iocs", "title", "blog url"]
DAYS_BACK = int(os.getenv("DAYS_BACK", "7"))
FEED_WORKERS = int(os.getenv("FEED_WORKERS", "8"))

Article = Dict[str, str]

# IoC kinds that alone justify creating a MISP event. Kinds outside this set
# (hashes, and the structurally-validated context IoCs) are still written to the
# event, but never trigger its creation on their own.
EVENT_TRIGGER_IOC_KEYS = {"urls", "ips", "fqdns", "browser_extensions"}


def _entry_get(entry, key: str, default=""):
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


def is_recent_article(date_str: str, cutoff_date: datetime) -> bool:
    if not date_str:
        return True
    try:
        article_date = parser.parse(date_str)
        if article_date.tzinfo:
            article_date = article_date.replace(tzinfo=None)
        return article_date >= cutoff_date
    except Exception as e:
        logger.warning(f"Failed to parse date '{date_str}': {e}")
        return True


def strip_scripts_and_get_text(soup: BeautifulSoup) -> str:
    for script in soup(["script", "style"]):
        script.decompose()
    return soup.get_text(separator="\n")


def decode_response_text(response: requests.Response) -> str:
    encoding = response.encoding if isinstance(response.encoding, str) else None
    apparent = response.apparent_encoding if isinstance(response.apparent_encoding, str) else None
    if (not encoding or encoding.lower() == "iso-8859-1") and apparent:
        encoding = apparent
    if not encoding:
        encoding = "utf-8"
    try:
        return response.content.decode(encoding, errors="replace")
    except Exception:
        try:
            return response.text
        except Exception:
            return ""


def response_text(response: requests.Response) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str) and text:
        return text
    return decode_response_text(response)


def fetch_url_content(url: str) -> str:
    logger.info(f"Fetching content from: {url}")
    try:
        if not url:
            return ""
        response = requests.get(
            url, timeout=10, verify=False, headers={"User-Agent": feedparser.USER_AGENT}
        )
        response.raise_for_status()
        html_text = response_text(response)
        return strip_scripts_and_get_text(BeautifulSoup(html_text, "html.parser"))
    except Exception as e:
        logger.warning(f"Failed to fetch content from {url}: {e}")
        return ""


def process_feed(
    vendor_name: str, feed_url: str, cutoff_date: datetime
) -> List[Article]:
    try:
        logger.info(f"Fetching RSS feed: {feed_url}")
        response = requests.get(
            feed_url,
            timeout=10,
            verify=False,
            headers={"User-Agent": feedparser.USER_AGENT},
        )
        response.raise_for_status()
        feed = feedparser.parse(response.content)

        if not hasattr(feed, "entries"):
            logger.warning(f"No entries found in feed: {feed_url}")
            return []

        articles = []
        for entry in reversed(feed.entries):
            pub_date = _entry_get(entry, "published", "")
            if is_recent_article(pub_date, cutoff_date):
                logger.info(f"Found recent article: {_entry_get(entry, 'title', '')}")
                content = ""
                entry_content = _entry_get(entry, "content")
                entry_summary = _entry_get(entry, "summary")
                entry_link = _entry_get(entry, "link", "")
                if entry_content:
                    content = (
                        entry_content[0].value
                        if isinstance(entry_content, list)
                        else entry_content
                    )
                    content = BeautifulSoup(content, "html.parser").get_text()
                elif entry_summary:
                    content = BeautifulSoup(entry_summary, "html.parser").get_text()
                else:
                    content = fetch_url_content(entry_link)

                articles.append(
                    {
                        "title": _entry_get(entry, "title", ""),
                        "date": pub_date,
                        "url": entry_link,
                        "content": content,
                        "vendor": vendor_name,
                    }
                )

        logger.info(f"Extracted {len(articles)} recent articles from {vendor_name}")
        return articles
    except Exception as e:
        logger.warning(f"Failed to fetch RSS feed {feed_url}: {e}")
        return []


def fetch_full_content(
    article: Article,
    crawl_links: bool = False,
    max_links: int = 30,
    crawl_same_domain: bool = False,
) -> List[Article]:
    url = article.get("url", "")
    logger.info(f"Fetching article content from: {url}")
    if not url:
        return []

    try:
        response = requests.get(
            url, timeout=10, verify=False, headers={"User-Agent": feedparser.USER_AGENT}
        )
        response.raise_for_status()
        soup = BeautifulSoup(response_text(response), "html.parser")
        article["content"] = strip_scripts_and_get_text(soup)
        articles = []

        if not crawl_links:
            articles.append(article)
            return articles

        seen_urls = {url}
        base_host = urlparse(url).netloc
        if base_host:
            seen_urls.add(base_host)

        for link_tag in soup.find_all("a", href=True):
            if len(articles) >= max_links:
                break
            href = link_tag.get("href", "").strip()
            if not href:
                continue
            full_url = urljoin(url, href)
            if (
                not full_url.lower().startswith(("http://", "https://"))
                or full_url in seen_urls
            ):
                continue
            if any(domain in full_url.lower() for domain in COMMON_DOMAINS):
                continue
            if urlparse(full_url).netloc == base_host and not crawl_same_domain:
                continue
            seen_urls.add(full_url)

            try:
                logger.info(f"Crawling linked content: {full_url}")
                r = requests.get(
                    full_url,
                    timeout=10,
                    verify=False,
                    headers={"User-Agent": feedparser.USER_AGENT},
                )
                r.raise_for_status()
                if not r.encoding or r.encoding.lower() == "iso-8859-1":
                    r.encoding = r.apparent_encoding or "utf-8"
                child_soup = BeautifulSoup(response_text(r), "html.parser")
                child_title = (
                    (child_soup.title.string or "").strip()
                    if child_soup.title and child_soup.title.string
                    else ""
                )
                articles.append(
                    {
                        "title": child_title or f"Linked content from {url}",
                        "date": to_yyyy_mm_dd(
                            article.get("date", datetime.now().strftime("%Y-%m-%d"))
                        ),
                        "url": full_url,
                        "content": strip_scripts_and_get_text(child_soup),
                        "vendor": article.get("vendor", ""),
                    }
                )
            except Exception as e:
                logger.debug(f"Failed to crawl linked content {full_url}: {e}")

        return articles
    except Exception as e:
        logger.warning(f"Failed to fetch article content from {url}: {e}")
        return []


def _event_info(article: Article) -> str:
    return f"[{article.get('vendor', '')}] {article.get('title', '')[:100]}"


def build_event(article: Article, iocs: Dict) -> Optional[MISPEvent]:
    """Build the MISPEvent in memory only -- no network access. Shared by
    add_event_to_misp and the --no-misp path so the stats rows are identical
    either way."""
    url = article.get("url", "")
    if url:
        article['url'] = re.sub(r"#.*", "", url)
    return create_misp_event_object(article, _event_info(article), iocs)


def add_event_to_misp(article: Article, iocs: Dict, misp: PyMISP) -> bool:
    event_info = _event_info(article)
    logger.info(f"Creating MISP event: {event_info}")
    try:
        existing_events = misp.search(eventinfo=event_info)
        if existing_events and len(existing_events) > 0:
            logger.info(f"Event with same title already exists, skipping: {event_info}")
            return False
        logger.info(f"No existing event found with title: {event_info}")
        event = build_event(article, iocs)
        if event:
            url = article.get("url", "")
            existing_attrs = misp.search(
                controller="attributes",
                value=url,
                type="url",
                category="External analysis",
                pythonify=True,
            )
            if existing_attrs:
                logger.info(
                    f"External analysis URL already exists in MISP, skipping: {url}"
                )
                return False
            misp.add_event(event, pythonify=True)
            return True
        logger.info("Skipping event creation")
    except Exception as e:
        logger.warning(f"Failed to create event: {e}")
    return False


def process_article(
    misp: Optional[PyMISP],
    article: Article,
    vendor: str,
    crawl_links: bool = False,
    crawl_same_domain: bool = False,
    stats: Optional[List[Dict[str, str]]] = None,
) -> bool:
    """With misp set, events are pushed to MISP as usual. With misp None
    (--no-misp) nothing leaves this process: the event is built in memory and
    its stats row is appended to stats instead."""
    logger.info(f"Processing article: {article.get('title', '')[:100]}...")
    articles = fetch_full_content(
        article, crawl_links=crawl_links, crawl_same_domain=crawl_same_domain
    )
    if not articles:
        return False

    event_created = False
    for current_article in articles:
        url = current_article.get("url", "")
        if misp is not None:
            try:
                existing_attrs = misp.search(
                    controller="attributes",
                    value=url,
                    type="url",
                    category="External analysis",
                    pythonify=True,
                )
                if existing_attrs:
                    logger.info(
                        f"External analysis URL already exists in MISP, skipping: {url}"
                    )
                    continue
            except Exception as e:
                logger.warning(
                    f"Failed to check existing MISP attributes for {url}: {e}"
                )

        logger.info(f"Processing {current_article.get('url', '')}")
        iocs = extract_iocs_from_content(current_article.get("content", ""))
        total_ioc_count = sum(len(ioc_set) for ioc_set in iocs.values())
        logger.info(f"Extracted {total_ioc_count} IOCs from {vendor}")

        for ioc_type, ioc_set in iocs.items():
            if ioc_set:
                logger.info(f"  {ioc_type}: {len(ioc_set)} items")
                sample_iocs = list(ioc_set)[:3]
                if sample_iocs:
                    logger.info(f"    Sample: {sample_iocs}")

        trigger_ioc_count = sum(
            len(values)
            for key, values in iocs.items()
            if key in EVENT_TRIGGER_IOC_KEYS
        )
        if trigger_ioc_count > 2:
            if misp is None:
                event = build_event(current_article, iocs)
                if event is not None:
                    if stats is not None:
                        stats.extend(stats_rows_from_events([event]))
                    event_created = True
            elif add_event_to_misp(current_article, iocs, misp):
                event_created = True
    return event_created


def stats_rows_from_events(events: List[MISPEvent]) -> List[Dict[str, str]]:
    """Turn events into stats rows. Shared by the MISP and the --no-misp paths so
    both produce identical columns; an event without an External analysis url
    attribute yields no row."""
    rows: List[Dict[str, str]] = []
    for event in events:
        vendor = (
            event.info.split("]")[0].strip("[").split("]")[0]
            if "]" in event.info
            else "Unknown"
        )
        ioc_count = len(event.attributes) - 1
        title = re.sub(r"^\[.*?\]\s*", "", event.info)
        for attr in event.attributes:
            if attr.category == "External analysis" and attr.type == "url":
                rows.append(
                    {
                        "date": event.date,
                        "vendor": vendor,
                        "iocs": ioc_count,
                        "title": title,
                        "blog url": attr.value,
                    }
                )
                break
    return rows


def _write_stats_csv(rows: List[Dict[str, str]]) -> None:
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=STATS_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def save_stats(misp: PyMISP) -> None:
    try:
        date_from = (datetime.now() - timedelta(days=int(DAYS_BACK))).strftime(
            "%Y-%m-%d"
        )
        date_to = datetime.now().strftime("%Y-%m-%d")
        events = misp.search(date_from=date_from, date_to=date_to, pythonify=True)

        _write_stats_csv(stats_rows_from_events(events))
        logger.info(f"Stats saved to {OUTPUT_CSV}")
        logger.info(
            f"Total: {sum(len(e.attributes) - 1 for e in events)} IOCs, {len(events)} events created"
        )
    except Exception as e:
        logger.error(f"Failed to save stats: {e}")


def _read_stats_csv(path: str) -> List[Dict[str, str]]:
    try:
        with open(path, "r", newline="", encoding="utf-8") as csvfile:
            return [
                {key: row.get(key, "") for key in STATS_FIELDNAMES}
                for row in csv.DictReader(csvfile)
            ]
    except FileNotFoundError:
        return []
    except Exception as e:
        logger.warning(f"Failed to read existing stats CSV {path}: {e}")
        return []


def merge_stats_rows(
    existing: List[Dict[str, str]], new: List[Dict[str, str]]
) -> List[Dict[str, str]]:
    """Deduplicate on blog url, existing rows winning. Without MISP there is no
    server-side duplicate check, so this covers both a link crawled twice in one
    run and a re-run on the same day."""
    merged: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for row in [*existing, *new]:
        url = str(row.get("blog url", ""))
        if url in seen:
            continue
        seen.add(url)
        merged.append(row)
    return merged


def _ioc_count(row: Dict[str, str]) -> int:
    """The merged rows include whatever an earlier run (or a hand edit) left in
    the CSV, so a non-numeric count must not turn a successful write into a
    reported failure."""
    try:
        return int(row.get("iocs", 0))
    except (TypeError, ValueError):
        return 0


def save_stats_local(rows: List[Dict[str, str]]) -> None:
    try:
        merged = merge_stats_rows(_read_stats_csv(OUTPUT_CSV), rows)
        _write_stats_csv(merged)
        logger.info(f"Stats saved to {OUTPUT_CSV}")
        logger.info(
            f"Total: {sum(_ioc_count(row) for row in merged)} IOCs, {len(merged)} articles"
        )
    except Exception as e:
        logger.error(f"Failed to save stats: {e}")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(
        description="Collect IoCs from threat intelligence RSS feeds."
    )
    arg_parser.add_argument(
        "--no-misp",
        action="store_true",
        help="Run without MISP: only write ioc_stats_YYYYMMDD.csv, never connect to MISP.",
    )
    return arg_parser.parse_args(argv)


def main(argv: Sequence[str] = ()) -> None:
    start_time = time.time()
    logger.info("Starting ThreatFeed Collector with iocextract")
    args = _parse_args(argv)

    misp: Optional[PyMISP] = None
    if args.no_misp:
        logger.info("Running with --no-misp: stats CSV only, no MISP connection")
    else:
        try:
            if not MISP_KEY:
                logger.error("MISP_KEY environment variable must be set")
                sys.exit(1)
            misp = PyMISP(MISP_URL, MISP_KEY, ssl=False)
            logger.info("MISP connection established")
        except Exception as e:
            logger.error(f"MISP connection failed: {e}")
            sys.exit(1)

    try:
        with open(RSS_FEEDS_CSV, "r") as f:
            reader = csv.reader(f)
            next(reader, None)
            feeds = [
                row
                for row in reader
                if row and len(row) >= 2 and not row[0].startswith("#")
            ]
    except FileNotFoundError:
        logger.error(f"RSS feeds file not found: {RSS_FEEDS_CSV}")
        sys.exit(1)

    logger.info(f"Processing {len(feeds)} RSS feeds")
    cutoff_date = datetime.now() - timedelta(days=DAYS_BACK)

    def _process_vendor_feed(row: List[str]) -> List[Dict[str, str]]:
        # The reader accepts rows with >= 2 columns, and README documents a
        # 3-column form, so pad instead of unpacking a fixed width.
        vendor, feed_url = row[0].strip(), row[1].strip()
        blog_url = row[2].strip() if len(row) > 2 else ""
        crawl_links = row[3].strip() if len(row) > 3 else ""
        logger.info(f"Processing vendor: {vendor}")
        should_crawl_links = str(crawl_links).lower() == "true"
        crawl_same_domain = False

        if feed_url:
            articles = process_feed(vendor, feed_url, cutoff_date)
        else:
            articles = [
                {
                    "title": f"{vendor} blog",
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "url": blog_url,
                    "content": "",
                    "vendor": vendor,
                }
            ]
            crawl_same_domain = True

        rows: List[Dict[str, str]] = []
        for article in articles:
            process_article(
                misp,
                article,
                vendor,
                should_crawl_links,
                crawl_same_domain,
                stats=rows,
            )
        return rows

    max_workers = max(1, min(FEED_WORKERS, len(feeds)))
    # Rows are collected here, in the main thread, so the workers never share
    # mutable state.
    collected_rows: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_vendor = {
            executor.submit(_process_vendor_feed, row): row[0] for row in feeds
        }
        for future in as_completed(future_to_vendor):
            vendor = future_to_vendor[future]
            try:
                collected_rows.extend(future.result())
                logger.info(f"Completed vendor: {vendor}")
            except Exception as exc:
                logger.warning(f"Vendor {vendor} failed: {exc}")

    if misp is None:
        save_stats_local(collected_rows)
    else:
        save_stats(misp)
    logger.info(f"Completed in {time.time() - start_time:.2f} seconds")


if __name__ == "__main__":
    main(sys.argv[1:])

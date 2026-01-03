import os
import csv
import re
import sys
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
import feedparser
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from pymisp import PyMISP
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

load_dotenv(Path(__file__).resolve().parent / ".env")

MISP_URL = os.getenv("MISP_URL", "")
MISP_KEY = None
if Path("/shared/authkey.txt").exists():
    MISP_KEY = Path("/shared/authkey.txt").read_text().strip()
else:
    MISP_KEY = os.getenv("MISP_KEY")
RSS_FEEDS_CSV = str(Path(__file__).resolve().parent / "config" / "rss_feeds.csv")
OUTPUT_CSV = f"ioc_stats_{datetime.now().strftime('%Y%m%d')}.csv"
DAYS_BACK = int(os.getenv("DAYS_BACK", "7"))
FEED_WORKERS = int(os.getenv("FEED_WORKERS", "8"))

Article = Dict[str, str]


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
        for entry in feed.entries:
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
        articles = [article]

        if not crawl_links:
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


def add_event_to_misp(article: Article, iocs: Dict, misp: PyMISP) -> bool:
    event_info = f"[{article.get('vendor', '')}] {article.get('title', '')[:100]}"
    logger.info(f"Creating MISP event: {event_info}")
    try:
        existing_events = misp.search(eventinfo=event_info)
        if existing_events and len(existing_events) > 0:
            logger.info(f"Event with same title already exists, skipping: {event_info}")
            return False
        url_attrs = misp.search(
            controller="attributes",
            value=article.get("url", ""),
            type="url",
            category="External analysis",
            pythonify=True,
        )
        if url_attrs and len(url_attrs) > 0:
            logger.info(
                f"Event with same External analysis URL already exists, skipping: {article.get('url', '')}"
            )
            return False
        logger.info(f"No existing event found with title: {event_info}")
        event = create_misp_event_object(article, event_info, iocs)
        if event:
            misp.add_event(event, pythonify=True)
            return True
        logger.info("No valid IOCs found, skipping event creation")
    except Exception as e:
        logger.warning(f"Failed to create event: {e}")
    return False


def process_article(
    misp: PyMISP,
    article: Article,
    vendor: str,
    crawl_links: bool = False,
    crawl_same_domain: bool = False,
) -> bool:
    logger.info(f"Processing article: {article.get('title', '')[:100]}...")
    articles = fetch_full_content(
        article, crawl_links=crawl_links, crawl_same_domain=crawl_same_domain
    )
    if not articles:
        return False

    event_created = False
    for current_article in articles:
        url = current_article.get("url", "")
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
            logger.warning(f"Failed to check existing MISP attributes for {url}: {e}")

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

        if sum(len(values) for key, values in iocs.items() if key != "hashes") > 2:
            if add_event_to_misp(current_article, iocs, misp):
                event_created = True
    return event_created


def save_stats(misp: PyMISP) -> None:
    try:
        date_from = (datetime.now() - timedelta(days=int(DAYS_BACK))).strftime(
            "%Y-%m-%d"
        )
        date_to = datetime.now().strftime("%Y-%m-%d")
        events = misp.search(date_from=date_from, date_to=date_to, pythonify=True)

        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile, fieldnames=["date", "vendor", "iocs", "title", "blog url"]
            )
            writer.writeheader()
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
                        writer.writerow(
                            {
                                "date": event.date,
                                "vendor": vendor,
                                "iocs": ioc_count,
                                "title": title,
                                "blog url": attr.value,
                            }
                        )
                        break
        logger.info(f"Stats saved to {OUTPUT_CSV}")
        logger.info(
            f"Total: {sum(len(e.attributes) - 1 for e in events)} IOCs, {len(events)} events created"
        )
    except Exception as e:
        logger.error(f"Failed to save stats: {e}")


def main() -> None:
    start_time = time.time()
    logger.info("Starting ThreatFeed Collector with iocextract")

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

    def _process_vendor_feed(row: List[str]) -> str:
        vendor, feed_url, blog_url, crawl_links = row
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

        for article in articles:
            process_article(
                misp, article, vendor, should_crawl_links, crawl_same_domain
            )
        return vendor

    max_workers = max(1, min(FEED_WORKERS, len(feeds)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_vendor = {
            executor.submit(_process_vendor_feed, row): row[0] for row in feeds
        }
        for future in as_completed(future_to_vendor):
            vendor = future_to_vendor[future]
            try:
                future.result()
                logger.info(f"Completed vendor: {vendor}")
            except Exception as exc:
                logger.warning(f"Vendor {vendor} failed: {exc}")

    save_stats(misp)
    logger.info(f"Completed in {time.time() - start_time:.2f} seconds")


if __name__ == "__main__":
    main()

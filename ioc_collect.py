#!/usr/bin/env python3
"""
ThreatFeed Collector - Functional approach for IoC extraction to MISP using iocextract
"""

import os
import csv
import re
import sys
import time
import logging
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

import requests
import urllib3
from datetime import datetime, timedelta
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

import feedparser
from bs4 import BeautifulSoup
from feedparser import USER_AGENT
from pymisp import PyMISP
from dateutil import parser

from ioc_extractor import extract_iocs_from_content, create_misp_event_object, COMMON_DOMAINS

urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables from .env if present
load_dotenv(Path(__file__).resolve().parent / ".env")

# Configuration
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_KEY')
if Path("/shared/authkey.txt").exists():
    MISP_KEY = Path("/shared/authkey.txt").read_text().strip()
elif not MISP_KEY:
    logger.error("MISP_KEY environment variable must be set")
    exit(1)

RSS_FEEDS_CSV = 'rss_feeds.csv'
if Path("/shared/threatfeed-collector/rss_feeds.csv"):
    RSS_FEEDS_CSV = "/shared/threatfeed-collector/rss_feeds.csv"

OUTPUT_CSV = os.getenv('OUTPUT_CSV', f'ioc_stats_{datetime.now().strftime("%Y%m%d")}.csv')
DAYS_BACK = int(os.getenv('DAYS_BACK'))


@dataclass
class Article:
    title: str = ""
    date: str = ""
    url: str = ""
    content: str = ""
    vendor: str = ""


def is_recent(date_str: str, cutoff_date: datetime) -> bool:
    if not date_str:
        return True
    try:
        article_date = parser.parse(date_str)
        if article_date.tzinfo:
            article_date = article_date.replace(tzinfo=None)
        return article_date >= cutoff_date
    except:
        return True


def extract_content(entry) -> str:
    url = entry.get('link', '')
    logger.info(f"Fetching content from: {url}")
    try:
        if url:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup(["script", "style"]):
                script.decompose()
            return soup.get_text(separator="\n")
        return ""
    except Exception as e:
        logger.warning(f"Failed to fetch content from {url}: {e}")
        return ""


def process_feed(vendor_name: str, feed_url: str, cutoff_date: datetime, crawl_links: bool = False) -> List[Article]:
    """Process RSS feed and extract recent articles"""
    try:
        logger.info(f"Fetching RSS feed: {feed_url}")
        response = requests.get(feed_url, timeout=10, verify=False, headers={'User-Agent': USER_AGENT})
        response.raise_for_status()
        feed = feedparser.parse(response.content)

        if not hasattr(feed, 'entries'):
            logger.warning(f"No entries found in feed: {feed_url}")
            return []

        articles: List[Article] = []
        for entry in feed.entries:
            pub_date = entry.get('published', '')
            if is_recent(pub_date, cutoff_date):
                logger.info(f"Found recent article: {entry.get('title', '')}")

                content = ""
                if hasattr(entry, 'content') and entry.content:
                    content = entry.content[0].value if isinstance(entry.content, list) else entry.content
                    content = BeautifulSoup(content, 'html.parser').get_text()
                elif hasattr(entry, 'summary') and entry.summary:
                    content = BeautifulSoup(entry.summary, 'html.parser').get_text()
                else:
                    content = extract_content(entry)

                articles.append(Article(
                    title=entry.get('title', ''),
                    date=pub_date,
                    url=entry.get('link', ''),
                    content=content,
                    vendor=vendor_name
                ))

        logger.info(f"Extracted {len(articles)} recent articles from {vendor_name}")
        return articles

    except Exception as e:
        logger.warning(f"Failed to fetch RSS feed {feed_url}: {e}")
        return []


def fetch_full_content(url: str, crawl_links: bool = False, max_links: int = 10) -> List[Tuple[str, str]]:
    def _soup_to_text(soup: BeautifulSoup) -> str:
        for script in soup(["script", "style"]):
            script.decompose()
        return soup.get_text(separator="\n")
    if not url:
        return []
    try:
        logger.info(f"Fetching article content from: {url}")
        result: List[Tuple[str, str]] = []
        response = requests.get(url, timeout=10, verify=False, headers={'User-Agent': USER_AGENT})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        base_text = _soup_to_text(soup)
        result.append((url, base_text))
        if not crawl_links:
            return result

        seen = set()
        base_host = urlparse(url).netloc
        if base_host:
            seen.add(base_host)
        seen.add(url)
        for a in soup.find_all('a', href=True):
            href = a.get('href', '').strip()
            if not href:
                continue
            full_url = urljoin(url, href)
            full_url_lower = urljoin(url, href).lower()
            if not full_url_lower.startswith(('http://', 'https://')):
                continue
            if any(dom in full_url_lower for dom in COMMON_DOMAINS):
                continue
            if full_url in seen or urlparse(full_url).netloc in seen:
                continue

            seen.add(full_url)
            seen.add(urlparse(full_url).netloc)
            if len(result) >= max_links:
                break
            try:
                logger.info(f"Crawling linked content: {full_url}")
                r = requests.get(full_url, timeout=10, verify=False, headers={'User-Agent': USER_AGENT})
                r.raise_for_status()
                child_soup = BeautifulSoup(r.text, 'html.parser')
                result.append((full_url, _soup_to_text(child_soup)))
            except Exception as e:
                logger.debug(f"Failed to crawl linked content {full_url}: {e}")
                continue
        return result

    except Exception as e:
        logger.warning(f"Failed to fetch article content from {url}: {e}")
        return []


def add_event(article: Article, iocs, misp: PyMISP) -> bool:
    event_info = f"[{article.vendor}] {article.title[:100]}"  # Truncate title
    logger.info(f"Creating MISP event: {event_info}")
    try:
        existing_events = misp.search(eventinfo=event_info)
        if existing_events and len(existing_events) > 0:
            logger.info(f"Event with same title already exists, skipping: {event_info}")
            return False
        logger.info(f"No existing event found with title: {event_info}")
        event = create_misp_event_object(article, event_info, iocs)
        if not event:
            logger.info("No valid IOCs found, skipping event creation")
            return False
        misp.add_event(event, pythonify=True)
        return True
    except Exception as e:
        logger.warning(f"Failed to create event: {e}")
        return False

def process_article(misp: PyMISP, article: Article, vendor: str, crawl_links: bool = False) -> bool:
    logger.info(f"Processing article: {article.title[:100]}...")
    url = article.url
    text = article.content
    fetch_res = fetch_full_content(url, crawl_links=crawl_links) if url else []
    if not fetch_res and text:
        fetch_res = [(url, text)]
    for url, content in fetch_res:
        article.url = url
        article.content = content or text

        iocs = extract_iocs_from_content(article.content)
        total_iocs = sum(len(s) for s in iocs.values())
        logger.info(f"Extracted {total_iocs} IOCs from {vendor}")

        for ioc_type, ioc_set in iocs.items():
            if ioc_set:
                logger.info(f"  {ioc_type}: {len(ioc_set)} items")
                sample_iocs = list(ioc_set)[:3]
                if sample_iocs:
                    logger.info(f"    Sample: {sample_iocs}")

        if total_iocs > 1:
            return add_event(article, iocs, misp)
    return False


def save_stats(misp: PyMISP) -> None:
    """Save statistics to CSV file"""
    try:
        date_from = datetime.now() - timedelta(days=int(DAYS_BACK))
        date_from = date_from.strftime('%Y-%m-%d')
        date_to = datetime.now().strftime('%Y-%m-%d')
        events = misp.search(date_from=date_from, date_to=date_to, pythonify=True)

        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['date', 'vendor', 'iocs', 'title', 'blog url']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for e in events:
                vendor = e.info.split(']')[0].strip('[').split(']')[0] if ']' in e.info else 'Unknown'
                iocs = len(e.attributes) - 1
                title = re.sub(r'^\[.*?\]\s*', '', e.info)
                for a in e.attributes:
                    if a.category == 'External analysis' and a.type == 'url':
                        blog_url = a.value
                        writer.writerow({'date': e.date, 'vendor': vendor, 'iocs': iocs, 'title': title, 'blog url': blog_url})
                        break
        logger.info(f"Stats saved to {OUTPUT_CSV}")
        total_iocs = sum(len(e.attributes) - 1 for e in events)
        total_created = len(events)
        logger.info(f"Total: {total_iocs} IOCs, {total_created} events created")
    except Exception as e:
        logger.error(f"Failed to save stats: {e}")


def main() -> None:
    start_time = time.time()
    logger.info("Starting ThreatFeed Collector with iocextract")

    try:
        misp = PyMISP(MISP_URL, MISP_KEY, ssl=False)
        logger.info("MISP connection established")
    except Exception as e:
        logger.error(f"MISP connection failed: {e}")
        sys.exit(1)

    try:
        with open(RSS_FEEDS_CSV, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)
            feeds = [(row[0], row[1], row[3]) for row in reader if row and len(row) >= 2 and not row[0].startswith('#')]
    except FileNotFoundError:
        logger.error(f"RSS feeds file not found: {RSS_FEEDS_CSV}")
        sys.exit(1)

    logger.info(f"Processing {len(feeds)} RSS feeds")
    cutoff_date = datetime.now() - timedelta(days=DAYS_BACK)
    for vendor, feed_url, crawl_links in feeds:
        logger.info(f"Processing vendor: {vendor}")
        crawl_links = True if str(crawl_links).lower() == "true" else False
        articles = process_feed(vendor, feed_url, cutoff_date, crawl_links)
        for article in articles:
            process_article(misp, article, vendor, crawl_links)

    save_stats(misp)
    elapsed = time.time() - start_time
    logger.info(f"Completed in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()


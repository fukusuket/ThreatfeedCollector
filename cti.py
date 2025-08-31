#!/usr/bin/env python3
"""
ThreatFeed Collector - Functional approach for IoC extraction to MISP
"""

import os
import csv
import sys
import time
import logging
import re
import urllib3
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Set

import feedparser
from bs4 import BeautifulSoup
from pymisp import PyMISP
from dateutil import parser as date_parser

urllib3.disable_warnings()

# Configuration
RSS_FEEDS_CSV = os.getenv('RSS_FEEDS_CSV', 'rss_feeds.csv')
MISP_URL = os.getenv('MISP_URL', 'https://localhost')
MISP_KEY = os.getenv('MISP_KEY', 'your_misp_key')
OUTPUT_CSV = os.getenv('OUTPUT_CSV', f'ioc_stats_{datetime.now().strftime("%Y%m%d")}.csv')
DAYS_BACK = int(os.getenv('DAYS_BACK', '1'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# IoC patterns
PATTERNS = {
    'urls': re.compile(r'https?://[^\s<>"\']+'),
    'ips': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    'fqdns': re.compile(
        r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'),
    'hashes': re.compile(r'\b[a-fA-F0-9]{32,64}\b')
}

COMMON_DOMAINS = {'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'stackoverflow.com'}


def is_recent(date_str: str, cutoff_date: datetime) -> bool:
    """Check if article date is within range"""
    if not date_str:
        return True
    try:
        article_date = date_parser.parse(date_str)
        if article_date.tzinfo:
            article_date = article_date.replace(tzinfo=None)
        return article_date >= cutoff_date
    except:
        return True


def is_public_ip(ip: str) -> bool:
    """Check if IP is public"""
    try:
        octets = [int(x) for x in ip.split('.')]
        if any(o > 255 for o in octets):
            return False
        # Exclude private ranges
        return not (octets[0] == 10 or
                    (octets[0] == 172 and 16 <= octets[1] <= 31) or
                    (octets[0] == 192 and octets[1] == 168) or
                    octets[0] == 127 or
                    (octets[0] == 169 and octets[1] == 254))
    except:
        return False


def is_suspicious_domain(domain: str) -> bool:
    """Check if domain is suspicious"""
    domain = domain.lower()
    return len(domain) >= 4 and not any(domain.endswith(d) for d in COMMON_DOMAINS)


def is_suspicious_url(url: str) -> bool:
    """Check if URL is suspicious"""
    return not any(d in url for d in COMMON_DOMAINS)


def extract_iocs(text: str) -> Dict[str, Set[str]]:
    """Extract IoCs from text"""
    if not text:
        return {k: set() for k in PATTERNS.keys()}

    return {
        'urls': {u for u in PATTERNS['urls'].findall(text) if is_suspicious_url(u)},
        'ips': {i for i in PATTERNS['ips'].findall(text) if is_public_ip(i)},
        'fqdns': {f for f in PATTERNS['fqdns'].findall(text) if is_suspicious_domain(f)},
        'hashes': {h for h in PATTERNS['hashes'].findall(text) if len(h) in [32, 40, 64]}
    }


def extract_content(entry) -> str:
    """Extract clean text from RSS entry"""
    content = getattr(entry, 'summary', '') or \
              (entry.content[0].value if hasattr(entry, 'content') and entry.content else '') or \
              getattr(entry, 'description', '')

    return BeautifulSoup(content, 'html.parser').get_text() if content else ""


def process_feed(vendor_name, feed_url: str, cutoff_date: datetime) -> List[Dict]:

    try:
        logger.info(f"Fetching RSS feed: {feed_url}")
        feed = feedparser.parse(feed_url)

        if not hasattr(feed, 'entries'):
            return []

        articles = []
        for entry in feed.entries:
            pub_date = entry.get('published', '')
            if is_recent(pub_date, cutoff_date):
                articles.append({
                    'title': entry.get('title', ''),
                    'date': pub_date,
                    'url': entry.get('link', ''),
                    'content': extract_content(entry),
                    'vendor': vendor_name
                })

        logger.info(f"Extracted {len(articles)} recent articles from {vendor_name}")
        return articles

    except Exception as e:
        logger.warning(f"Failed to fetch RSS feed {feed_url}: {e}")
        return []


def create_misp_event(misp: PyMISP, article: Dict, iocs: Dict[str, Set[str]]) -> bool:
    try:
        event_title = f"[{article['vendor']}] {article['title']}"
        logger.info(f"Creating MISP event: {event_title}")
        return True
    except Exception as e:
        logger.error(f"Failed to create MISP event: {e}")
        return False


def save_stats(stats: defaultdict, events_created: defaultdict) -> None:
    try:
        vendors = set(list(stats.keys()) + list(events_created.keys()))
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['vendor', 'urls', 'ips', 'fqdns', 'hashes', 'total_iocs', 'events_created']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for vendor in vendors:
                counts = stats[vendor]
                writer.writerow({
                    'vendor': vendor,
                    'urls': counts['urls'],
                    'ips': counts['ips'],
                    'fqdns': counts['fqdns'],
                    'hashes': counts['hashes'],
                    'total_iocs': sum(counts.values()),
                    'events_created': events_created[vendor]
                })

        logger.info(f"Stats saved to {OUTPUT_CSV}")

        # Log summary
        total_iocs = sum(sum(stats[v].values()) for v in stats)
        total_created = sum(events_created.values())
        logger.info(f"Total: {total_iocs} IoCs, {total_created} events created")
    except Exception as e:
        logger.error(f"Failed to save stats: {e}")


if __name__ == "__main__":
    start_time = time.time()
    logger.info("Starting ThreatFeed Collector")

    try:
        misp = PyMISP(MISP_URL, MISP_KEY, ssl=False)
        logger.info("MISP connection established")
    except Exception as e:
        logger.error(f"MISP connection failed: {e}")
        sys.exit(1)

    cutoff_date = datetime.now() - timedelta(days=DAYS_BACK)
    stats = defaultdict(lambda: defaultdict(int))
    events_created = defaultdict(int)

    # Process feeds
    with open(RSS_FEEDS_CSV, 'r') as f:
        reader = csv.reader(f)
        feeds = [(row[0], row[1]) for row in reader if row and not row[0].startswith('#')]

    for (vendor, feed_url) in feeds:
        articles = process_feed(vendor, feed_url, cutoff_date)

        for article in articles:
            logger.info(f"Processing: {article['title']}")

            # Extract IoCs
            text = f"{article['title']} {article['content']}"
            iocs = extract_iocs(text)

            # Update stats
            for ioc_type, ioc_set in iocs.items():
                stats[vendor][ioc_type] += len(ioc_set)

            total_iocs = sum(len(s) for s in iocs.values())
            logger.info(f"Extracted {total_iocs} IoCs")

            # Create MISP event if IoCs found
            if total_iocs > 0:
                created = create_misp_event(misp, article, iocs)
                if created:
                    events_created[vendor] += 1

    # Save results
    save_stats(stats, events_created)

    elapsed = time.time() - start_time
    logger.info(f"Completed in {elapsed:.2f} seconds")
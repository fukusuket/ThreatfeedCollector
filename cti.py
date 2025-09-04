#!/usr/bin/env python3
"""
ThreatFeed Collector - Functional approach for IoC extraction to MISP using iocextract
"""

import os
import csv
import ipaddress
import re
import sys
import time
import logging
import requests
import urllib3
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Set

import feedparser
from bs4 import BeautifulSoup
from feedparser import USER_AGENT
from pymisp import PyMISP, MISPEvent
from dateutil import parser
import iocextract
from pymispwarninglists import WarningLists

urllib3.disable_warnings()

# Configuration
RSS_FEEDS_CSV = os.getenv('RSS_FEEDS_CSV', 'rss_feeds.csv')
MISP_URL = os.getenv('MISP_URL', 'https://localhost')
MISP_KEY = os.getenv('MISP_KEY', 'youre_api_key_here')
OUTPUT_CSV = os.getenv('OUTPUT_CSV', f'ioc_stats_{datetime.now().strftime("%Y%m%d")}.csv')
DAYS_BACK = int(os.getenv('DAYS_BACK', '14'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

COMMON_DOMAINS = {'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'stackoverflow.com',
                  'twitter.com', 'facebook.com', 'linkedin.com', 'instagram.com', 'youtube.com', 'pastebin.com',
                  'virustotal.com', 'urlvoid.com', 'hybrid-analysis.com', 'any.run', 'joesandbox.com'}

WARNING_LIST = WarningLists(slow_search=True)

# RFC 3986
URL_REGEX = re.compile(
    r'^(?:http|https|ftp)://'
    r'(?:\S+(?::\S*)?@)?'
    r'(?:'
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})|'
    r'(?P<host>[a-zA-Z0-9\-\.]+)'
    r')'
    r'(?::\d{2,5})?'
    r'(?:[/?#][^\s]*)?'
    r'$'
)

def is_recent(date_str: str, cutoff_date: datetime) -> bool:
    """Check if article date is within range"""
    if not date_str:
        return True
    try:
        article_date = parser.parse(date_str)
        if article_date.tzinfo:
            article_date = article_date.replace(tzinfo=None)
        return article_date >= cutoff_date
    except:
        return True


def is_ipv4_strict(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
        if ip.is_global:
            return True
        if WARNING_LIST.search(s):
            logger.info(f"Excluding IP from warning list: {s})")
            return False
        return True
    except ipaddress.AddressValueError:
        return False

def is_suspicious_domain(domain: str) -> bool:
    """Check if domain is suspicious (not in common domains list)"""
    domain = domain.lower()
    if WARNING_LIST.search(domain):
        logger.info(f"Excluding domain from warning list: {domain}")
        return False
    # Extract base domain for comparison
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        base_domain = '.'.join(domain_parts[-2:])
        return len(domain) >= 4 and base_domain not in COMMON_DOMAINS
    return len(domain) >= 4


def is_suspicious_url(url: str) -> bool:
    """Check if URL is suspicious (not containing common domains)"""
    url_lower = url.lower()
    if WARNING_LIST.search(url_lower):
        logger.info(f"Excluding url from warning list: {url_lower}")
        return False
    return not any(d in url_lower for d in COMMON_DOMAINS)


def is_valid_url(url: str) -> bool:
    if "redacted" in url.lower():
        return False
    if url.count('.') < 1:
        return False
    return bool(URL_REGEX.match(url))


def extract_iocs(text: str) -> Dict[str, Set[str]]:
    """Extract IoCs from text using iocextract library"""
    if not text:
        return {'urls': set(), 'ips': set(), 'fqdns': set(), 'hashes': set()}

    iocs = {'urls': set(), 'ips': set(), 'fqdns': set(), 'hashes': set()}

    try:
        # Extract URLs (refang=True to convert defanged URLs back to normal format)
        urls = set(iocextract.extract_urls(text, refang=True))
        domains = {re.sub(":.*", "", u.replace("http:","")) for u in urls if not is_valid_url(u)}
        domains = {d for d in domains if not is_ipv4_strict(d)}
        urls = {u for u in urls if is_valid_url(u)}
        iocs['urls'] = {u for u in urls if is_suspicious_url(u)}

        # Extract IPv4 addresses
        ips = set(iocextract.extract_ipv4s(text, refang=True))

        # Extract domains from URLs and standalone domains
        # First extract domains from URLs we found
        for url in urls:
            try:
                if '://' in url:
                    # Simple ip address extraction from URL
                    if re.match(r'\d{1,3}(\.\d{1,3}){3}', url):
                        ip_part = re.match(r'\d{1,3}(\.\d{1,3}){3}', url).group(0)
                        if is_ipv4_strict(ip_part):
                            ips.add(ip_part)
                    else:
                        domain_part = url.split('://')[1].split('/')[0].split(':')[0]
                        if is_suspicious_domain(domain_part):
                            domains.add(domain_part)

            except:
                continue

        iocs['fqdns'] = {d for d in domains if is_suspicious_domain(d)}
        iocs['ips'] = {i for i in ips if is_ipv4_strict(i)}
        # Extract hashes
        hashes = set(iocextract.extract_hashes(text))
        # Filter by hash length (MD5=32, SHA1=40, SHA256=64, SHA512=128)
        iocs['hashes'] = {h for h in hashes if len(h) in [32, 40, 64, 128]}

    except Exception as e:
        logger.warning(f"Error extracting IOCs: {e}")
        # Fallback to empty sets if extraction fails

    return iocs


def extract_content(entry) -> str:
    """Extract content from RSS entry"""
    url = entry.get('link', '')
    logger.info(f"Fetching content from: {url}")
    try:
        if url:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            content = response.text
            # Use BeautifulSoup to extract text content
            soup = BeautifulSoup(content, 'html.parser')
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()
            return soup.get_text()
        return ""
    except Exception as e:
        logger.warning(f"Failed to fetch content from {url}: {e}")
        return ""


def process_feed(vendor_name: str, feed_url: str, cutoff_date: datetime) -> List[Dict]:
    """Process RSS feed and extract recent articles"""
    try:
        logger.info(f"Fetching RSS feed: {feed_url}")
        response = requests.get(feed_url, timeout=10, verify=False, headers={'User-Agent': USER_AGENT})
        response.raise_for_status()
        feed = feedparser.parse(response.content)

        if not hasattr(feed, 'entries'):
            logger.warning(f"No entries found in feed: {feed_url}")
            return []

        articles = []
        for entry in feed.entries:
            pub_date = entry.get('published', '')
            if is_recent(pub_date, cutoff_date):
                logger.info(f"Found recent article: {entry.get('title', '')}")

                # Try to get content from multiple sources
                content = ""
                # First try content field
                if hasattr(entry, 'content') and entry.content:
                    content = entry.content[0].value if isinstance(entry.content, list) else entry.content
                    content = BeautifulSoup(content, 'html.parser').get_text()
                # Then try summary
                elif hasattr(entry, 'summary') and entry.summary:
                    content = BeautifulSoup(entry.summary, 'html.parser').get_text()
                # Finally try to fetch from link
                else:
                    content = extract_content(entry)

                articles.append({
                    'title': entry.get('title', ''),
                    'date': pub_date,
                    'url': entry.get('link', ''),
                    'content': content,
                    'vendor': vendor_name
                })

        logger.info(f"Extracted {len(articles)} recent articles from {vendor_name}")
        return articles

    except Exception as e:
        logger.warning(f"Failed to fetch RSS feed {feed_url}: {e}")
        return []


def to_yyyy_mm_dd(date_str: str) -> str:
    try:
        dt = parser.parse(date_str)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return datetime.utcnow().strftime("%Y-%m-%d")

def create_misp_event(misp: PyMISP, article: Dict, iocs: Dict[str, Set[str]]) -> bool:
    """Create MISP event with extracted IOCs"""
    try:
        event_title = f"[{article['vendor']}] {article['title'][:100]}"  # Truncate title
        logger.info(f"Creating MISP event: {event_title}")

        # Check if event with same title already exists
        try:
            existing_events = misp.search(eventinfo=event_title)
            if existing_events and len(existing_events) > 0:
                logger.info(f"Event with same title already exists, skipping: {event_title}")
                return False
            logger.info(f"No existing event found with title: {event_title}")
        except Exception as e:
            logger.warning(f"Failed to search for existing events: {e}")
            # Continue with creation if search fails

        # Create new MISP event
        event = MISPEvent()
        event.info = event_title
        event.date = to_yyyy_mm_dd(article['date'])
        #event.add_tag('workflow:state="draft"')
        event.add_attribute(type="url", value=article['url'], category='External analysis', to_ids=False)
        # Add attributes
        for ioc_type, ioc_set in iocs.items():
            for ioc in ioc_set:
                if ioc_type == 'urls':
                    attr_type = 'url'
                elif ioc_type == 'ips':
                    attr_type = 'ip-dst'
                elif ioc_type == 'fqdns':
                    attr_type = 'hostname'
                elif ioc_type == 'hashes':
                    # Determine hash type by length
                    if len(ioc) == 32:
                        attr_type = 'md5'
                    elif len(ioc) == 40:
                        attr_type = 'sha1'
                    elif len(ioc) == 64:
                        attr_type = 'sha256'
                    elif len(ioc) == 128:
                        attr_type = 'sha512'
                    else:
                        continue
                else:
                    continue
                try:
                    event.add_attribute(type=attr_type, value=ioc, category='Network activity', to_ids=True)
                except Exception as e:
                    logger.warning(f"Failed to add attribute {ioc} of type {attr_type}: {e}")
        misp.add_event(event, pythonify=True)
        logger.info(f"Created MISP Event.")
        return True

    except Exception as e:
        logger.error(f"Failed to create MISP event: {e}")
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


if __name__ == "__main__":
    start_time = time.time()
    logger.info("Starting ThreatFeed Collector with iocextract")

    try:
        misp = PyMISP(MISP_URL, MISP_KEY, ssl=False)
        logger.info("MISP connection established")
    except Exception as e:
        logger.error(f"MISP connection failed: {e}")
        sys.exit(1)

    cutoff_date = datetime.now() - timedelta(days=DAYS_BACK)
    events_created = defaultdict(int)

    # Process feeds
    try:
        with open(RSS_FEEDS_CSV, 'r') as f:
            reader = csv.reader(f)
            # Skip header row
            next(reader, None)
            feeds = [(row[0], row[1]) for row in reader if row and len(row) >= 2 and not row[0].startswith('#')]
    except FileNotFoundError:
        logger.error(f"RSS feeds file not found: {RSS_FEEDS_CSV}")
        sys.exit(1)

    logger.info(f"Processing {len(feeds)} RSS feeds")

    for vendor, feed_url in feeds:
        logger.info(f"Processing vendor: {vendor}")
        articles = process_feed(vendor, feed_url, cutoff_date)

        for article in articles:
            logger.info(f"Processing article: {article['title'][:100]}...")
            url = article['url']
            if url:
                try:
                    response = requests.get(url, timeout=10, verify=False, headers={'User-Agent': USER_AGENT})
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # Remove script and style elements
                    for script in soup(["script", "style"]):
                        script.decompose()
                    text = soup.get_text()
                except Exception as e:
                    logger.warning(f"Failed to fetch article content from {url}: {e}")
                    continue
            else:
                text = article['content']
            iocs = extract_iocs(text)

            total_iocs = sum(len(s) for s in iocs.values())
            logger.info(f"Extracted {total_iocs} IOCs from {vendor}")

            # Log details of extracted IOCs
            for ioc_type, ioc_set in iocs.items():
                if ioc_set:
                    logger.info(f"  {ioc_type}: {len(ioc_set)} items")
                    # Log first few items for debugging
                    sample_iocs = list(ioc_set)[:3]
                    if sample_iocs:
                        logger.info(f"    Sample: {sample_iocs}")

            # Create MISP event if IOCs found
            if total_iocs > 0:
                create_misp_event(misp, article, iocs)
    save_stats(misp)

    elapsed = time.time() - start_time
    logger.info(f"Completed in {elapsed:.2f} seconds")
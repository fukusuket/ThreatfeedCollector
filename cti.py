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
from pathlib import Path

from dotenv import load_dotenv

import requests
import urllib3
from datetime import datetime, timedelta
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import feedparser
from bs4 import BeautifulSoup
from feedparser import USER_AGENT
from pymisp import PyMISP, MISPEvent
from dateutil import parser
import iocextract
from pymispwarninglists import WarningLists

from thunt_advisor import analyze_threat_article

urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables from .env if present
load_dotenv(Path(__file__).resolve().parent / ".env")

# Configuration
RSS_FEEDS_CSV = 'rss_feeds.csv'
MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_KEY')
if Path("/shared/authkey.txt").exists():
    MISP_KEY = Path("/shared/authkey.txt").read_text().strip()
elif not MISP_KEY:
    logger.error("MISP_KEY environment variable must be set")
    exit(1)

if Path("/shared/threatfeed-collector/rss_feeds.csv"):
    RSS_FEEDS_CSV = "/shared/threatfeed-collector/rss_feeds.csv"

OUTPUT_CSV = os.getenv('OUTPUT_CSV', f'ioc_stats_{datetime.now().strftime("%Y%m%d")}.csv')
DAYS_BACK = int(os.getenv('DAYS_BACK'))

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
        if not ip.is_global:
            return False
        r = WARNING_LIST.search(s)
        if ("List of known IPv4 public DNS resolvers" in str(r)
                or "List of known Zscaler IP address ranges" in str(r)
                or "List of known Cloudflare IP ranges" in str(r)
                or "List of known Akamai IP ranges" in str(r)
                or "List of known Google IP address ranges" in str(r)):
            logger.info(f"Excluding IP from warning list: {s})")
            return False
        return True
    except ipaddress.AddressValueError:
        return False

def is_suspicious_domain(domain: str) -> bool:
    """Check if domain is suspicious (not in common domains list)"""
    domain = domain.lower()
    if len(domain) > 253 or not domain or domain.endswith(".txt") or domain.endswith(".exe") or domain.endswith(".zip"):
        return False
    if re.match(r'\d{1,3}(\.\d{1,3}){3}', domain):
        return False
    if WARNING_LIST.search(domain):
        logger.info(f"Excluding domain from warning list: {domain}")
        return False
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        base_domain = '.'.join(domain_parts[-2:])
        return len(domain) >= 4 and base_domain not in COMMON_DOMAINS
    return len(domain) >= 4


def is_suspicious_url(url: str) -> bool:
    """Check if URL is suspicious (not containing common domains)"""
    url_lower = url.lower()
    if not '/' in url and not url.startswith('http'):
        return False
    if WARNING_LIST.search(url_lower):
        logger.info(f"Excluding url from warning list: {url_lower}")
        return False
    return not any(d in url_lower for d in COMMON_DOMAINS)


def is_valid_url(url: str) -> bool:
    if "redacted" in url.lower():
        return False
    if url.count('.') < 1:
        return False

    suspicious_extensions = {
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js',
        '.jar', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        '.msi', '.deb', '.rpm', '.dmg', '.pkg', 'pdf', '.doc', '.docx',
        '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.txt', '.xml', '.json',
        '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.rb'
    }

    try:
        if '://' in url.lower():
            domain_part = url.split('://')[1].split('/')[0].split(':')[0]
            if any(domain_part.endswith(ext) for ext in suspicious_extensions):
                return False
    except:
        pass

    return bool(URL_REGEX.match(url))


def extract_lines_with_defang_markers(text: str) -> str:
    if not text:
        return ""
    return "\n".join(
        line for line in text.splitlines()
        if "[.]" in line or "[://]" in line
    )

def extract_iocs(text: str) -> Dict[str, Set[str]]:
    """Extract IoCs from text using iocextract library"""
    if not text:
        return {'urls': set(), 'ips': set(), 'fqdns': set(), 'hashes': set()}

    iocs = {'urls': set(), 'ips': set(), 'fqdns': set(), 'hashes': set()}

    try:
        hashes = set(iocextract.extract_hashes(text))
        iocs['hashes'] = {h for h in hashes if len(h) in [32, 40, 64, 128]}

        text = extract_lines_with_defang_markers(text)
        text = text.replace("hxxp", "http").replace("[://]", "://")
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


def process_feed(vendor_name: str, feed_url: str, cutoff_date: datetime, crawl_links: bool = False) -> List[Dict]:
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

def trim_markdown_fence(text: str) -> str:
    m = re.match(r"^\s*```(?:\w+)?\s*\n?(.*?)\n?\s*```\s*$", text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()


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
        event.add_attribute(type="comment", value=article['content'], category='Other', to_ids=False)

        # TODO PoC for AI analysis summary
        # ai_summary = analyze_threat_article(content=article['content'])
        # event.add_event_report(name="[en]_[gpt-5.2]_" + event_title, content=trim_markdown_fence(ai_summary), distribution=0)
        #
        # ai_summary_jp = analyze_threat_article(content=ai_summary, prompt_path="/shared/threatfeed-collector/prompt-translate.md")
        # event.add_event_report(name="[en_jp]_[gpt-5.2]_" + event_title, content=trim_markdown_fence(ai_summary_jp), distribution=0)
        #
        # ai_summary = analyze_threat_article(content=article['content'], additional_pre_context="Translate the response into Japanese. Avoid polite speech (desu/masu form) and honorifics; use a plain, neutral tone.")
        # event.add_event_report(name="[jp]_[gpt-5.2]_" + event_title, content=trim_markdown_fence(ai_summary), distribution=0)

        misp.add_event(event, pythonify=True)
        logger.info(f"Created MISP Event.")
        return True

    except Exception as e:
        logger.error(f"Failed to create MISP event: {e}")
        return False


def load_feeds(csv_path: str) -> List[tuple]:
    """Load RSS feed definitions from CSV."""
    try:
        with open(csv_path, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)
            return [(row[0], row[1], row[3]) for row in reader if row and len(row) >= 2 and not row[0].startswith('#')]
    except FileNotFoundError:
        logger.error(f"RSS feeds file not found: {csv_path}")
        raise


def fetch_full_content(url: str, crawl_links: bool = False, max_links: int = 5) -> str:
    """Fetch full article content with basic sanitization."""
    if not url:
        return ""
    try:
        logger.info(f"Fetching article content from: {url}")
        response = requests.get(url, timeout=10, verify=False, headers={'User-Agent': USER_AGENT})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup(["script", "style"]):
            script.decompose()
        base_text = soup.get_text()

        if not crawl_links:
            return base_text

        seen = set()
        base_host = urlparse(url).netloc
        if base_host:
            seen.add(base_host)
        seen.add(url)
        linked_texts = []
        for a in soup.find_all('a', href=True):
            href = a.get('href', '').strip()
            if not href:
                continue
            full_url = urljoin(url, href)
            if not full_url.startswith(('http://', 'https://')):
                continue
            if full_url in seen or urlparse(full_url).netloc in seen:
                continue
            seen.add(full_url)
            seen.add(urlparse(full_url).netloc)
            if len(linked_texts) >= max_links:
                break
            try:
                logger.info(f"Crawling linked content: {full_url}")
                r = requests.get(full_url, timeout=10, verify=False, headers={'User-Agent': USER_AGENT})
                r.raise_for_status()
                child_soup = BeautifulSoup(r.text, 'html.parser')
                for script in child_soup(["script", "style"]):
                    script.decompose()
                linked_texts.append(child_soup.get_text())
            except Exception as e:
                logger.debug(f"Failed to crawl linked content {full_url}: {e}")
                continue

        if linked_texts:
            return base_text + "\n\n" + "\n\n".join(linked_texts)
        return base_text

    except Exception as e:
        logger.warning(f"Failed to fetch article content from {url}: {e}")
        return ""


def process_article(misp: PyMISP, article: Dict, vendor: str, crawl_links: bool = False) -> bool:
    logger.info(f"Processing article: {article['title'][:100]}...")
    url = article.get('url', '')
    text = article.get('content', '')
    fetched_text = fetch_full_content(url, crawl_links=crawl_links) if url else ""
    article['content'] = fetched_text or text

    iocs = extract_iocs(article['content'])
    total_iocs = sum(len(s) for s in iocs.values())
    logger.info(f"Extracted {total_iocs} IOCs from {vendor}")

    for ioc_type, ioc_set in iocs.items():
        if ioc_set:
            logger.info(f"  {ioc_type}: {len(ioc_set)} items")
            sample_iocs = list(ioc_set)[:3]
            if sample_iocs:
                logger.info(f"    Sample: {sample_iocs}")

    if total_iocs > 1:
        return create_misp_event(misp, article, iocs)
    return False


def process_vendor_feed(misp: PyMISP, vendor: str, feed_url: str, cutoff_date: datetime, crawl_links: bool = False) -> None:
    logger.info(f"Processing vendor: {vendor}")
    articles = process_feed(vendor, feed_url, cutoff_date, crawl_links)
    for article in articles:
        process_article(misp, article, vendor, crawl_links)


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

    cutoff_date = datetime.now() - timedelta(days=DAYS_BACK)

    try:
        feeds = load_feeds(RSS_FEEDS_CSV)
    except FileNotFoundError:
        sys.exit(1)

    logger.info(f"Processing {len(feeds)} RSS feeds")
    for vendor, feed_url, crawl_links in feeds:
        crawl_links = True if str(crawl_links).lower() == "true" else False
        process_vendor_feed(misp, vendor, feed_url, cutoff_date, crawl_links)

    save_stats(misp)
    elapsed = time.time() - start_time
    logger.info(f"Completed in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()


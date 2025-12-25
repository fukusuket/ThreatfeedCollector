import ipaddress
import re
import logging
from datetime import datetime
from typing import Dict, Set, Optional
from pymisp import MISPEvent
from dateutil import parser
import iocextract
from pymispwarninglists import WarningLists

from ioc_collect import Article
from thunt_advisor import analyze_threat_article

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

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

EXT_ID_PATTERN = re.compile(r'[a-p]{32}')

COMMON_DOMAINS = {'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'stackoverflow.com', 'nist.gov', 'x.com', 'feedburner.com',
                  'twitter.com', 'facebook.com', 'linkedin.com', 'instagram.com', 'youtube.com', 'pastebin.com', 'infosec.exchange',
                  'virustotal.com', 'urlvoid.com', 'hybrid-analysis.com', 'any.run', 'joesandbox.com', 'bleepingcomputer.com', 'thehackernews', 'web3adspanels.com'}

WARNING_LIST = WarningLists(slow_search=True)


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

def to_yyyy_mm_dd(date_str: str) -> str:
    try:
        dt = parser.parse(date_str)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return datetime.utcnow().strftime("%Y-%m-%d")

def trim_markdown_fence(text: str) -> str:
    m = re.match(r"^\s*```(?:\w+)?\s*\n?(.*?)\n?\s*```\s*$", text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()

def extract_lines_with_defang_markers(text: str) -> str:
    if not text:
        return ""
    return "\n".join(
        line for line in text.splitlines()
        if "[.]" in line or "[://]" in line
    )

def extract_iocs_from_content(text: str) -> Dict[str, Set[str]]:
    """Extract IoCs from text using iocextract library"""
    if not text:
        return {'urls': set(), 'ips': set(), 'fqdns': set(), 'hashes': set(), 'browser_extensions': set()}

    iocs = {'urls': set(), 'ips': set(), 'fqdns': set(), 'hashes': set(),'browser_extensions': set()}

    try:
        hashes = set(iocextract.extract_hashes(text))
        iocs['hashes'] = {h for h in hashes if len(h) in [32, 40, 64, 128]}
        browser_extensions = set(EXT_ID_PATTERN.findall(text or ""))
        iocs['browser_extensions'] = browser_extensions

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

def create_misp_event_object(article: Article, event_info: str, iocs: Dict[str, Set[str]]) -> Optional[MISPEvent]:
    try:
        event = MISPEvent()
        event.info = event_info
        event.date = to_yyyy_mm_dd(article.date)
        event.add_attribute(type="url", value=article.url, category='External analysis', to_ids=False)
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
                elif ioc_type == 'browser_extensions':
                    event.add_attribute(type='chrome-extension-id', value=ioc, category='Payload installation', to_ids=True)
                    logger.info(f"Added browser extension ID: {ioc}")
                    continue
                else:
                    continue
                try:
                    event.add_attribute(type=attr_type, value=ioc, category='Network activity', to_ids=True)
                except Exception as e:
                    logger.warning(f"Failed to add attribute {ioc} of type {attr_type}: {e}")
        event.add_attribute(type="comment", value=article.content, category='Other', to_ids=False)

        # TODO PoC for AI analysis summary
        # ai_summary = analyze_threat_article(content=article.content, title=article.title, url=article.url)
        # event.add_event_report(name="[en]_" + event_info, content=trim_markdown_fence(ai_summary), distribution=0)
        #
        # ai_summary_jp = analyze_threat_article(content=ai_summary, prompt_path="/shared/threatfeed-collector/prompt-translate.md")
        # event.add_event_report(name="[jp]_" + event_info, content=trim_markdown_fence(ai_summary_jp), distribution=0)

        logger.info(f"Created MISP Event object.")
        return event

    except Exception as e:
        logger.error(f"Failed to create MISP event object: {e}")
        return None

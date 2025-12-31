import ipaddress
import re
import logging
from datetime import datetime
from typing import Dict, Set, Optional
from pymisp import MISPEvent
from dateutil import parser
import iocextract
from pymispwarninglists import WarningLists

from thunt_advisor import analyze_threat_article

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
)
logger = logging.getLogger(__name__)

URL_REGEX = re.compile(
    r"^(?:http|https|ftp)://"
    r"(?:\S+(?::\S*)?@)?"
    r"(?:"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})|"
    r"(?P<host>[a-zA-Z0-9\-\.]+)"
    r")"
    r"(?::\d{2,5})?"
    r"(?:[/?#][^\s]*)?"
    r"$"
)

EXTENSION_ID_PATTERN = re.compile(r"[a-p]{32}")

COMMON_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "stackoverflow.com",
    "nist.gov",
    "x.com",
    "feedburner.com",
    "twitter.com",
    "facebook.com",
    "linkedin.com",
    "instagram.com",
    "youtube.com",
    "pastebin.com",
    "infosec.exchange",
    "virustotal.com",
    "urlvoid.com",
    "hybrid-analysis.com",
    "any.run",
    "joesandbox.com",
    "bleepingcomputer.com",
    "thehackernews",
    "web3adspanels.com",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".pif",
    ".vbs",
    ".js",
    ".jar",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
    ".msi",
    ".deb",
    ".rpm",
    ".dmg",
    ".pkg",
    "pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".rtf",
    ".txt",
    ".xml",
    ".json",
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
}

WARNING_LISTS = WarningLists(slow_search=True)


def is_global_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if not ip.is_global:
            return False
        result = WARNING_LISTS.search(ip_str)
        if any(
            name in str(result)
            for name in [
                "IPv4 public DNS resolvers",
                "Zscaler IP",
                "Cloudflare IP",
                "Akamai IP",
                "Google IP",
            ]
        ):
            logger.info(f"Excluding IP from warning list: {ip_str}")
            return False
        return True
    except ipaddress.AddressValueError:
        return False
    except Exception as e:
        logger.debug(f"Failed to check global IPv4 for {ip_str}: {e}")
        return False


def is_suspicious_domain(domain: str) -> bool:
    domain = domain.lower()
    if (
        len(domain) > 253
        or not domain
        or any(domain.endswith(ext) for ext in [".txt", ".exe", ".zip"])
    ):
        return False
    if re.match(r"\d{1,3}(\.\d{1,3}){3}", domain):
        return False
    if WARNING_LISTS.search(domain):
        logger.info(f"Excluding domain from warning list: {domain}")
        return False
    domain_parts = domain.split(".")
    if len(domain_parts) >= 2:
        base_domain = ".".join(domain_parts[-2:])
        return len(domain) >= 4 and base_domain not in COMMON_DOMAINS
    return len(domain) >= 4


def is_suspicious_url(url: str) -> bool:
    url_lower = url.lower()
    if "/" not in url and not url.startswith("http"):
        return False
    if WARNING_LISTS.search(url_lower):
        logger.info(f"Excluding url from warning list: {url_lower}")
        return False
    return not any(domain in url_lower for domain in COMMON_DOMAINS)


def is_valid_url(url: str) -> bool:
    lower_url = url.lower()
    if "redacted" in lower_url or lower_url.count(".") < 1:
        return False
    try:
        if "://" in lower_url:
            domain_part = url.split("://")[1].split("/")[0].split(":")[0]
            if any(domain_part.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                return False
    except Exception as e:
        logger.debug(f"Failed to validate url {url}: {e}")
        return False
    return bool(URL_REGEX.match(url))


def to_yyyy_mm_dd(date_str: str) -> str:
    try:
        return parser.parse(date_str).strftime("%Y-%m-%d")
    except Exception:
        return datetime.utcnow().strftime("%Y-%m-%d")


def trim_markdown_fence(text: str) -> str:
    match = re.match(r"^\s*```(?:\w+)?\s*\n?(.*?)\n?\s*```\s*$", text, re.DOTALL)
    return match.group(1).strip() if match else text.strip()


def extract_iocs_from_content(text: str) -> Dict[str, Set[str]]:
    if not text:
        return {
            "urls": set(),
            "ips": set(),
            "fqdns": set(),
            "hashes": set(),
            "browser_extensions": set(),
        }

    iocs = {
        "urls": set(),
        "ips": set(),
        "fqdns": set(),
        "hashes": set(),
        "browser_extensions": set(),
    }

    try:
        hashes = set(iocextract.extract_hashes(text))
        iocs["hashes"] = {h for h in hashes if len(h) in [32, 40, 64, 128]}
        iocs["browser_extensions"] = set(EXTENSION_ID_PATTERN.findall(text or ""))

        defanged_lines = "\n".join(
            line for line in text.splitlines() if "[.]" in line or "[://]" in line
        )
        refanged_text = defanged_lines.replace("hxxp", "http").replace("[://]", "://")
        extracted_urls = set(iocextract.extract_urls(refanged_text, refang=True))

        non_url_domains = {
            re.sub(":.*", "", u.replace("http:", ""))
            for u in extracted_urls
            if not is_valid_url(u)
        }
        non_url_domains = {d for d in non_url_domains if not is_global_ipv4(d)}

        valid_urls = {u for u in extracted_urls if is_valid_url(u)}
        iocs["urls"] = {u for u in valid_urls if is_suspicious_url(u)}

        ip_addresses = set(iocextract.extract_ipv4s(refanged_text, refang=True))

        domains = set(non_url_domains)
        for url in valid_urls:
            try:
                if "://" in url:
                    if re.match(r"\d{1,3}(\.\d{1,3}){3}", url):
                        ip_match = re.match(r"\d{1,3}(\.\d{1,3}){3}", url)
                        if ip_match and is_global_ipv4(ip_match.group(0)):
                            ip_addresses.add(ip_match.group(0))
                    else:
                        domain_part = url.split("://")[1].split("/")[0].split(":")[0]
                        if is_suspicious_domain(domain_part):
                            domains.add(domain_part)
            except Exception as e:
                logger.debug(f"Failed to parse url {url}: {e}")
                continue

        iocs["fqdns"] = {d for d in domains if is_suspicious_domain(d)}
        iocs["ips"] = {ip for ip in ip_addresses if is_global_ipv4(ip)}

    except Exception as e:
        logger.warning(f"Error extracting IOCs: {e}")

    return iocs


def create_misp_event_object(
    article: Dict, event_info: str, iocs: Dict[str, Set[str]]
) -> Optional[MISPEvent]:
    try:
        event = MISPEvent()
        event.info = event_info
        event.date = to_yyyy_mm_dd(article.get("date", ""))
        event.add_attribute(
            type="url",
            value=article.get("url", ""),
            category="External analysis",
            to_ids=False,
        )
        for ioc_type, ioc_set in iocs.items():
            for ioc_value in ioc_set:
                if ioc_type == "urls":
                    attr_type = "url"
                elif ioc_type == "ips":
                    attr_type = "ip-dst"
                elif ioc_type == "fqdns":
                    attr_type = "hostname"
                elif ioc_type == "hashes":
                    hash_types = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
                    attr_type = hash_types.get(len(ioc_value))
                    if not attr_type:
                        continue
                elif ioc_type == "browser_extensions":
                    try:
                        event.add_attribute(
                            type="chrome-extension-id",
                            value=ioc_value,
                            category="Payload installation",
                            to_ids=True,
                        )
                        logger.info(f"Added browser extension ID: {ioc_value}")
                    except Exception as e:
                        logger.warning(
                            f"Failed to add browser extension {ioc_value}: {e}"
                        )
                    continue
                else:
                    continue
                try:
                    event.add_attribute(
                        type=attr_type,
                        value=ioc_value,
                        category="Network activity",
                        to_ids=True,
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to add attribute {ioc_value} of type {attr_type}: {e}"
                    )
        event.add_attribute(
            type="comment",
            value=article.get("content", ""),
            category="Other",
            to_ids=False,
        )

        # TODO PoC for AI analysis summary
        # ai_summary = analyze_threat_article(content=article.get('content', ''), title=article.get('title', ''), url=article.get('url', ''))
        # event.add_event_report(name="[en]_" + event_info, content=trim_markdown_fence(ai_summary), distribution=0)
        #
        # ai_summary_jp = analyze_threat_article(content=ai_summary, prompt_path="/shared/threatfeed-collector/prompt-translate.md")
        # event.add_event_report(name="[jp]_" + event_info, content=trim_markdown_fence(ai_summary_jp), distribution=0)

        logger.info("Created MISP Event object.")
        return event

    except Exception as e:
        logger.error(f"Failed to create MISP event object: {e}")
        return None

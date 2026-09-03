import base64
import hashlib
import ipaddress
import re
import logging
from datetime import datetime
from typing import Dict, Set, Optional
from pymisp import MISPEvent, MISPObject
from dateutil import parser
import iocextract
from pymispwarninglists import WarningLists
from pathlib import Path

# from thunt_advisor import analyze_threat_article

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"

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

# Self-delimiting, structurally verifiable IoCs. These are scanned from the full
# text (not only the defanged lines) because they are never defanged in practice.
CVE_PATTERN = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE)
ONION_V3_PATTERN = re.compile(r"\b([a-z2-7]{56})\.onion\b", re.IGNORECASE)
ONION_V3_CHECKSUM_SALT = b".onion checksum"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BTC_BASE58_PATTERN = re.compile(
    r"(?<![0-9A-Za-z])[13][1-9A-HJ-NP-Za-km-z]{25,39}(?![0-9A-Za-z])"
)
BTC_BECH32_PATTERN = re.compile(
    r"(?<![0-9A-Za-z])bc1[02-9ac-hj-np-z]{11,71}(?![0-9A-Za-z])", re.IGNORECASE
)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# Monero mainnet: standard/subaddress (95 chars) and integrated (106 chars).
# The Keccak-256 checksum is not verifiable with hashlib alone, so the prefix,
# alphabet and exact length carry the precision here.
XMR_PATTERN = re.compile(
    r"(?<![0-9A-Za-z])[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?"
    r"(?![0-9A-Za-z])"
)

def _load_set_from_file(path: Path) -> Set[str]:
    try:
        with path.open("r", encoding="utf-8") as f:
            items = {
                line.strip().lower()
                for line in f
                if line.strip() and not line.lstrip().startswith("#")
            }
        if not items:
            logger.warning(f"No entries found in {path}, falling back to defaults")
            return set()
        return items
    except FileNotFoundError:
        logger.warning(f"Config file not found: {path}, using defaults")
        return set()
    except Exception as e:
        logger.warning(f"Failed to load config {path}: {e}")
        return set()


COMMON_DOMAINS = _load_set_from_file(CONFIG_DIR / "common_domains.txt")
SUSPICIOUS_EXTENSIONS = _load_set_from_file( CONFIG_DIR / "suspicious_extensions.txt")
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


def _trim_to_ioc_section(markdown_text: str) -> str:
    content = trim_markdown_fence(markdown_text)
    lines = content.splitlines()
    start_idx = None
    for idx, line in enumerate(lines):
        if line.strip().lower().startswith("### ioc"):
            start_idx = idx
            break
    if start_idx is None:
        return ""
    return "\n".join(lines[start_idx:]).strip()


def extract_cves(text: str) -> Set[str]:
    """Extract CVE IDs, normalized to upper case."""
    return {match.upper() for match in CVE_PATTERN.findall(text)}


def is_valid_onion_v3(address: str) -> bool:
    """Verify a v3 onion address against its embedded ed25519 checksum.

    An address is base32(pubkey[32] || checksum[2] || version[1]), where the
    checksum is sha3-256(".onion checksum" || pubkey || version)[:2]. v2
    addresses carry no checksum and are deliberately not accepted.
    """
    label = address.lower().removesuffix(".onion")
    if len(label) != 56:
        return False
    try:
        decoded = base64.b32decode(label.upper())
    except Exception as e:
        logger.debug(f"Failed to decode onion address {label}: {e}")
        return False
    if len(decoded) != 35:
        return False
    pubkey, checksum, version = decoded[:32], decoded[32:34], decoded[34:]
    if version != b"\x03":
        return False
    expected = hashlib.sha3_256(ONION_V3_CHECKSUM_SALT + pubkey + version).digest()[:2]
    if checksum != expected:
        logger.info(f"Excluding onion address with bad checksum: {label}")
        return False
    return True


def extract_onion_addresses(text: str) -> Set[str]:
    """Extract checksum-valid v3 onion addresses, including defanged ones."""
    refanged = text.replace("[.]", ".")
    return {
        f"{match.lower()}.onion"
        for match in ONION_V3_PATTERN.findall(refanged)
        if is_valid_onion_v3(match)
    }


def _base58_decode(value: str) -> Optional[bytes]:
    number = 0
    for char in value:
        index = BASE58_ALPHABET.find(char)
        if index < 0:
            return None
        number = number * 58 + index
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + decoded


def _bech32_checksum_const(data: str) -> int:
    """Return the polymod constant for the bech32 variant of `data`, or 0."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    values = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    values += [BECH32_CHARSET.index(c) for c in data]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            checksum ^= generator[i] if ((top >> i) & 1) else 0
    return checksum


def is_valid_btc_address(address: str) -> bool:
    """Verify a mainnet Bitcoin address against its checksum.

    Base58Check addresses must carry a valid double-SHA256 checksum and a
    mainnet version byte; bech32/bech32m addresses must satisfy the BIP-173 /
    BIP-350 polymod for their witness version.
    """
    if BTC_BASE58_PATTERN.fullmatch(address):
        decoded = _base58_decode(address)
        if decoded is None or len(decoded) != 25:
            return False
        if decoded[0] not in (0x00, 0x05):
            return False
        expected = hashlib.sha256(hashlib.sha256(decoded[:21]).digest()).digest()[:4]
        if decoded[21:] != expected:
            logger.info(f"Excluding btc address with bad checksum: {address}")
            return False
        return True
    if BTC_BECH32_PATTERN.fullmatch(address):
        lowered = address.lower()
        if address != lowered and address != address.upper():
            return False  # bech32 forbids mixed case
        data = lowered[3:]  # strip the "bc1" hrp and separator
        if any(c not in BECH32_CHARSET for c in data):
            return False
        witness_version = BECH32_CHARSET.index(data[0])
        expected = 1 if witness_version == 0 else 0x2BC830A3
        if _bech32_checksum_const(data) != expected:
            logger.info(f"Excluding btc address with bad checksum: {address}")
            return False
        return True
    return False


def extract_btc_addresses(text: str) -> Set[str]:
    """Extract checksum-valid mainnet Bitcoin addresses."""
    candidates = set(BTC_BASE58_PATTERN.findall(text))
    candidates |= set(BTC_BECH32_PATTERN.findall(text))
    return {c for c in candidates if is_valid_btc_address(c)}


def is_valid_xmr_address(address: str) -> bool:
    """Check a Monero address by prefix, alphabet and exact length."""
    return bool(XMR_PATTERN.fullmatch(address)) and len(address) in (95, 106)


def extract_xmr_addresses(text: str) -> Set[str]:
    """Extract well-formed Monero mainnet addresses."""
    return {m for m in XMR_PATTERN.findall(text) if is_valid_xmr_address(m)}


def extract_iocs_from_content(text: str) -> Dict[str, Set[str]]:
    iocs = {
        "urls": set(),
        "ips": set(),
        "fqdns": set(),
        "hashes": set(),
        "browser_extensions": set(),
        "cves": set(),
        "onion_addresses": set(),
        "btc_addresses": set(),
        "xmr_addresses": set(),
    }
    if not text:
        return iocs

    try:
        hashes = set(iocextract.extract_hashes(text))
        iocs["hashes"] = {h for h in hashes if len(h) in [32, 40, 64, 128]}
        iocs["browser_extensions"] = set(EXTENSION_ID_PATTERN.findall(text or ""))
        iocs["cves"] = extract_cves(text)
        iocs["onion_addresses"] = extract_onion_addresses(text)
        iocs["btc_addresses"] = extract_btc_addresses(text)
        iocs["xmr_addresses"] = extract_xmr_addresses(text)

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
        # An onion address already written as `onion-address` must not also be
        # written as a `hostname`. Only checksum-valid v3 addresses are removed,
        # so anything not captured above (e.g. v2) still ships as an fqdn.
        iocs["fqdns"] -= {
            d for d in iocs["fqdns"] if d.lower() in iocs["onion_addresses"]
        }
        iocs["ips"] = {ip for ip in ip_addresses if is_global_ipv4(ip)}

    except Exception as e:
        logger.warning(f"Error extracting IOCs: {e}")

    return iocs


def _add_extracted_ioc_attributes(event: MISPEvent, iocs: Dict[str, Set[str]]) -> None:
    for ioc_type, ioc_set in iocs.items():
        for ioc_value in ioc_set:
            ioc_type = ioc_type.lower()
            try:
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
                elif ioc_type == "cves":
                    event.add_attribute(
                        type="vulnerability",
                        value=ioc_value,
                        category="External analysis",
                        to_ids=False,
                    )
                    logger.info(f"Added CVE: {ioc_value}")
                    continue
                elif ioc_type == "onion_addresses":
                    event.add_attribute(
                        type="onion-address",
                        value=ioc_value,
                        category="Network activity",
                        to_ids=True,
                    )
                    logger.info(f"Added onion address: {ioc_value}")
                    continue
                elif ioc_type == "btc_addresses":
                    event.add_attribute(
                        type="btc",
                        value=ioc_value,
                        category="Financial fraud",
                        to_ids=False,
                    )
                    logger.info(f"Added btc address: {ioc_value}")
                    continue
                elif ioc_type == "xmr_addresses":
                    event.add_attribute(
                        type="xmr",
                        value=ioc_value,
                        category="Financial fraud",
                        to_ids=False,
                    )
                    logger.info(f"Added xmr address: {ioc_value}")
                    continue
                elif ioc_type == "browser_extensions":
                    event.add_attribute(
                        type="chrome-extension-id",
                        value=ioc_value,
                        category="Payload installation",
                        to_ids=True,
                    )
                    logger.info(f"Added browser extension ID: {ioc_value}")
                    continue
                else:
                    continue
                event.add_attribute(
                    type=attr_type,
                    value=ioc_value,
                    category="Network activity",
                    to_ids=True,
                )
            except Exception as e:
                logger.warning(f"Failed to add attribute for {ioc_type}={ioc_value}: {e}")


def _parse_ioc_rows_from_markdown(markdown_text: str) -> list[Dict[str, str]]:
    rows = []
    for line in markdown_text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0].lower() in {"type", "---"}:
            continue
        type_cell, value_cell, context_cell = cells[0], cells[1], cells[2]
        type_lower = type_cell.lower()
        if "file" in type_lower:
            kind = "file"
        elif "command" in type_lower or "process" in type_lower:
            kind = "command"
        elif "registry" in type_lower:
            kind = "registry"
        elif "email" in type_lower:
            kind = "email"
        else:
            continue
        rows.append({"kind": kind, "value": value_cell, "context": context_cell})
    return rows


def _add_ai_iocs_from_summary(event: MISPEvent, ai_summary: str) -> None:
    ioc_section = _trim_to_ioc_section(ai_summary)
    if not ioc_section:
        return
    ioc_rows = _parse_ioc_rows_from_markdown(ioc_section)
    for row in ioc_rows:
        try:
            comment = row.get("context", "").strip("`'\"")
            value = row.get("value", "").strip("`'\"")
            if row["kind"] == "command":
                obj = MISPObject(name="command-line")
                obj.add_attribute("command_line", value)
                obj.comment = row.get("context", "")
                event.add_object(obj)
            elif row["kind"] == "file":
                event.add_attribute(category="Persistence mechanism", type="filename", value=value, comment=comment)
            elif row["kind"] == "registry":
                event.add_attribute(category="Persistence mechanism", type="regkey", value=value, comment=comment)
            elif row["kind"] == "email":
                event.add_attribute(category="Payload delivery", type="email-src", value=value, comment=comment)
        except Exception as e:
            logger.warning(f"Failed to add AI summary iocs {row}: {e}")


def _build_query_sample_markdown(iocs: Dict[str, Set[str]]) -> str:
    ips = sorted(iocs.get("ips", set()))
    fqdns = sorted(iocs.get("fqdns", set()))
    browser_extensions = sorted(iocs.get("browser_extensions", set()))
    hashes = sorted(iocs.get("hashes", set()))
    if not ips and not fqdns and not browser_extensions:
        return ""
    lines = ["### Query Sample"]
    if ips:
        lines.append("```")
        lines.append(f"ips: ({"|".join(ips)})")
        lines.append("```")
    if fqdns:
        lines.append("```")
        lines.append(f"fqdns: ({"|".join(fqdns)})")
        lines.append("```")
    if browser_extensions:
        lines.append("```")
        lines.append(f"browser_extensions: ({"|".join(browser_extensions)})")
        lines.append("```")
    if hashes:
        lines.append("```")
        lines.append(f"hashes: ({"|".join(hashes)})")
        lines.append("```")
    return "\n".join(lines)


def create_misp_event_object(article: Dict, event_info: str, iocs: Dict[str, Set[str]]) -> Optional[MISPEvent]:
    try:
        event = MISPEvent()
        event.info = event_info
        event.date = to_yyyy_mm_dd(article.get("date", ""))
        url = article.get("url", "")
        event.add_attribute(type="url", value=url, category="External analysis", to_ids=False)
        #event.add_attribute(type="comment", value=article.get("content", ""), category="Other", to_ids=False)
        _add_extracted_ioc_attributes(event, iocs)
        # ai_summary_en = analyze_threat_article(
        #     content=article.get("content", ""),
        #     title=article.get("title", ""),
        #     url=article.get("url", ""),
        # )
        #
        # event.add_event_report(name="[en]_" + event_info, content=trim_markdown_fence(ai_summary_en), distribution=0)
        # _add_ai_iocs_from_summary(event, ai_summary_en)
        #
        # ai_summary_jp = analyze_threat_article(
        #     content=ai_summary_en,
        #     prompt_path=str(Path(__file__).resolve().parent / "config" / "prompt-translate.md")
        # )
        # query_sample = _build_query_sample_markdown(iocs)
        # if query_sample:
        #     ai_summary_jp = f"{ai_summary_jp}\n\n{query_sample}"
        #
        # event.add_event_report(name="[jp]_" + event_info, content=trim_markdown_fence(ai_summary_jp), distribution=0)

        logger.info("Created MISP Event object.")
        return event

    except Exception as e:
        logger.error(f"Failed to create MISP event object: {e}")
        return None

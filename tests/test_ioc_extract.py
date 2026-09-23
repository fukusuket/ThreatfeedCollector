import sys
import types
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import ioc_extract


@pytest.fixture(autouse=True)
def reset_warning_lists(monkeypatch):
    dummy = MagicMock()
    dummy.search.return_value = None
    monkeypatch.setattr(ioc_extract, "WARNING_LISTS", dummy)
    # Tests flip the filtering switch; restore it so order cannot matter.
    monkeypatch.setattr(ioc_extract, "USE_WARNING_LISTS", ioc_extract.USE_WARNING_LISTS)
    return dummy


def test_is_global_ipv4_accepts_global_and_not_in_warning_list(reset_warning_lists):
    reset_warning_lists.search.return_value = None
    assert ioc_extract.is_global_ipv4("8.8.8.8") is True


def test_is_global_ipv4_rejects_private_and_warning_list(reset_warning_lists):
    reset_warning_lists.search.return_value = "Google IP"
    assert ioc_extract.is_global_ipv4("10.0.0.1") is False
    assert ioc_extract.is_global_ipv4("8.8.8.8") is False


def test_is_suspicious_domain_rejects_common_and_warning_list(reset_warning_lists):
    reset_warning_lists.search.return_value = None
    assert ioc_extract.is_suspicious_domain("example.com") is True
    assert ioc_extract.is_suspicious_domain("google.com") is False
    reset_warning_lists.search.return_value = "listed"
    assert ioc_extract.is_suspicious_domain("evil.test") is False


def test_is_suspicious_domain_rejects_bad_forms():
    assert ioc_extract.is_suspicious_domain("") is False
    assert ioc_extract.is_suspicious_domain("256.0.0.1") is False
    assert ioc_extract.is_suspicious_domain("a.txt") is False


def test_is_suspicious_url_filters_common_and_warning(reset_warning_lists):
    reset_warning_lists.search.return_value = None
    assert ioc_extract.is_suspicious_url("http://mal.example.com/path") is True
    assert ioc_extract.is_suspicious_url("http://google.com/search") is False
    reset_warning_lists.search.return_value = "listed"
    assert ioc_extract.is_suspicious_url("http://mal.example.com") is False


def test_is_suspicious_url_requires_slash_or_scheme():
    assert ioc_extract.is_suspicious_url("example.com") is False


# Ad/analytics/share-widget and reference sites that carry no threat intel.
@pytest.mark.parametrize(
    "host",
    [
        "doubleclick.net",
        "googletagmanager.com",
        "google-analytics.com",
        "googlesyndication.com",
        "googleadservices.com",
        "adnxs.com",
        "taboola.com",
        "outbrain.com",
        "hotjar.com",
        "hs-analytics.net",
        "hubspot.com",
        "addthis.com",
        "sharethis.com",
        "addtoany.com",
        "mitre.org",
        "cisa.gov",
        "first.org",
    ],
)
def test_common_domains_exclude_noise_hosts(host):
    assert ioc_extract.is_suspicious_domain(f"sub.{host}") is False
    assert ioc_extract.is_suspicious_url(f"https://sub.{host}/path") is False


# Services attackers routinely abuse must stay reportable; the URL check is a
# substring match, so a careless entry (e.g. cloudflare.com, t.co) would hide them.
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.trycloudflare.com/payload",
        "https://t.me/stealer_logs",
        "https://evil.workers.dev/x",
        "https://evil.pages.dev/x",
        "https://abc.ngrok.io/x",
        "https://discord.com/api/webhooks/1/x",
        "https://bit.ly/abc",
        pytest.param(
            "https://www.dropbox.com/s/x/payload.zip",
            marks=pytest.mark.xfail(
                strict=True,
                reason="known bug: existing 'x.com' entry substring-matches 'dropbox.com'",
            ),
        ),
    ],
)
def test_common_domains_keep_abused_services(url):
    assert ioc_extract.is_suspicious_url(url) is True
    assert ioc_extract.is_suspicious_domain(url.split("/")[2]) is True


def test_is_valid_url_rejects_redacted_and_suspicious_extensions():
    assert ioc_extract.is_valid_url("https://example.com/redacted") is False
    assert ioc_extract.is_valid_url("https://example.com/file.exe") is False


def test_is_valid_url_accepts_normal_http_url():
    assert ioc_extract.is_valid_url("https://example.net/path") is True
    assert ioc_extract.is_valid_url("ftp://host.test") is True


def test_trim_markdown_fence_strips_fence():
    fenced = """```text\nhello\n```"""
    assert ioc_extract.trim_markdown_fence(fenced) == "hello"


def test_trim_markdown_fence_passthrough_plain():
    assert ioc_extract.trim_markdown_fence("plain text") == "plain text"


def test_to_yyyy_mm_dd_parses_valid_date():
    assert ioc_extract.to_yyyy_mm_dd("2024-01-02") == "2024-01-02"


def test_to_yyyy_mm_dd_fallbacks_on_error(monkeypatch):
    fixed = datetime(2024, 5, 6)
    monkeypatch.setattr(
        ioc_extract, "datetime", MagicMock(utcnow=MagicMock(return_value=fixed))
    )
    assert ioc_extract.to_yyyy_mm_dd("not-a-date") == "2024-05-06"


def test_extract_iocs_filters_warning_and_common(monkeypatch, reset_warning_lists):
    text = """
    hxxp[:]//malicious[.]example/path
    8.8.8.8
    deadbeefdeadbeefdeadbeefdeadbeef
    extension id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    """
    monkeypatch.setattr(
        ioc_extract,
        "iocextract",
        types.SimpleNamespace(
            extract_hashes=lambda t: ["deadbeefdeadbeefdeadbeefdeadbeef"],
            extract_urls=lambda t, refang=True: ["http://malicious.example/path"],
            extract_ipv4s=lambda t, refang=True: ["8.8.8.8"],
        ),
    )
    reset_warning_lists.search.return_value = None
    result = ioc_extract.extract_iocs_from_content(text)
    assert result["hashes"] == {"deadbeefdeadbeefdeadbeefdeadbeef"}
    assert result["urls"] == {"http://malicious.example/path"}
    assert result["fqdns"] == {"malicious.example"}
    assert result["ips"] == {"8.8.8.8"}
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in result["browser_extensions"]


def test_extract_iocs_ignores_empty():
    assert ioc_extract.extract_iocs_from_content("") == {
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


def test_extract_cves_normalizes_case():
    text = "Exploits cve-2024-3400 and CVE-1999-0001 (also CVE-2023-1234567)."
    assert ioc_extract.extract_cves(text) == {
        "CVE-2024-3400",
        "CVE-1999-0001",
        "CVE-2023-1234567",
    }


def test_extract_cves_rejects_malformed():
    text = """
    CVE-20-1234 CVE-2024-123 CVE-1899-1234 CVE-20244-1234
    CVE-2024-12345678 XCVE-2024-1234 CVE2024-1234
    """
    assert ioc_extract.extract_cves(text) == set()


def test_extract_iocs_collects_cves(monkeypatch, reset_warning_lists):
    monkeypatch.setattr(
        ioc_extract,
        "iocextract",
        types.SimpleNamespace(
            extract_hashes=lambda t: [],
            extract_urls=lambda t, refang=True: [],
            extract_ipv4s=lambda t, refang=True: [],
        ),
    )
    result = ioc_extract.extract_iocs_from_content("patched in CVE-2024-3400 advisory")
    assert result["cves"] == {"CVE-2024-3400"}


VALID_ONION = "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead"

# Addresses below come from public references (Bitcoin genesis output, BIP-173
# and BIP-350 test vectors), not from the implementation.
BTC_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
BTC_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
BTC_BECH32M = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
# Public Monero donation address (getmonero.org), 95 chars.
XMR_ADDRESS = (
    "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjy"
    "Pbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H"
)


def test_is_valid_onion_v3_accepts_checksum_match():
    assert ioc_extract.is_valid_onion_v3(VALID_ONION) is True
    assert ioc_extract.is_valid_onion_v3(f"{VALID_ONION}.onion") is True
    assert ioc_extract.is_valid_onion_v3(f"{VALID_ONION}.onion".upper()) is True


def test_is_valid_onion_v3_rejects_bad_checksum_and_v2():
    # single character flipped inside the public key part
    tampered = "b" + VALID_ONION[1:]
    assert ioc_extract.is_valid_onion_v3(tampered) is False
    # v2 addresses (16 chars) carry no checksum and are not accepted
    assert ioc_extract.is_valid_onion_v3("expyuzz4wqqyqhjn.onion") is False
    # not base32 at all
    assert ioc_extract.is_valid_onion_v3("8" * 56) is False


def test_extract_onion_addresses_requires_suffix_and_refangs():
    text = f"""
    c2: {VALID_ONION}[.]onion
    mirror: {VALID_ONION.upper()}.onion
    not an address: {VALID_ONION}
    tampered: b{VALID_ONION[1:]}.onion
    """
    assert ioc_extract.extract_onion_addresses(text) == {f"{VALID_ONION}.onion"}


def test_create_misp_event_object_adds_onion_attribute(monkeypatch):
    mock_event = MagicMock()
    monkeypatch.setattr(ioc_extract, "MISPEvent", MagicMock(return_value=mock_event))
    monkeypatch.setattr(
        ioc_extract, "to_yyyy_mm_dd", MagicMock(return_value="2024-02-03")
    )
    article = {"date": "ignored", "url": "http://source", "content": "body"}

    ioc_extract.create_misp_event_object(
        article, "info", {"onion_addresses": {f"{VALID_ONION}.onion"}}
    )

    mock_event.add_attribute.assert_any_call(
        type="onion-address",
        value=f"{VALID_ONION}.onion",
        category="Network activity",
        to_ids=True,
    )


def test_extract_iocs_keeps_valid_onion_out_of_fqdns(monkeypatch, reset_warning_lists):
    """A v3 onion is written as onion-address only, never also as a hostname."""
    monkeypatch.setattr(
        ioc_extract,
        "iocextract",
        types.SimpleNamespace(
            extract_hashes=lambda t: [],
            extract_urls=lambda t, refang=True: [f"http://{VALID_ONION}.onion/gate"],
            extract_ipv4s=lambda t, refang=True: [],
        ),
    )
    result = ioc_extract.extract_iocs_from_content(
        f"leak site: {VALID_ONION}[.]onion/gate"
    )
    assert result["onion_addresses"] == {f"{VALID_ONION}.onion"}
    assert result["fqdns"] == set()


def test_extract_iocs_keeps_unverified_onion_as_fqdn(monkeypatch, reset_warning_lists):
    """v2 onions are not written as onion-address, so they must stay fqdns."""
    v2 = "expyuzz4wqqyqhjn.onion"
    monkeypatch.setattr(
        ioc_extract,
        "iocextract",
        types.SimpleNamespace(
            extract_hashes=lambda t: [],
            extract_urls=lambda t, refang=True: [f"http://{v2}/gate"],
            extract_ipv4s=lambda t, refang=True: [],
        ),
    )
    result = ioc_extract.extract_iocs_from_content("leak site: expyuzz4wqqyqhjn[.]onion")
    assert result["onion_addresses"] == set()
    assert result["fqdns"] == {v2}


def test_is_valid_btc_address_accepts_known_good():
    assert ioc_extract.is_valid_btc_address(BTC_P2PKH) is True
    assert ioc_extract.is_valid_btc_address(BTC_P2SH) is True
    assert ioc_extract.is_valid_btc_address(BTC_BECH32) is True
    assert ioc_extract.is_valid_btc_address(BTC_BECH32M) is True
    assert ioc_extract.is_valid_btc_address(BTC_BECH32.upper()) is True


def test_is_valid_btc_address_rejects_tampered_and_non_mainnet():
    # last character changed -> checksum mismatch
    assert ioc_extract.is_valid_btc_address(BTC_P2PKH[:-1] + "b") is False
    assert ioc_extract.is_valid_btc_address(BTC_BECH32[:-1] + "5") is False
    assert ioc_extract.is_valid_btc_address(BTC_BECH32M[:-1] + "1") is False
    # testnet
    assert (
        ioc_extract.is_valid_btc_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty"
        )
        is False
    )
    # bech32 forbids mixed case
    assert (
        ioc_extract.is_valid_btc_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7KV8f3t4"
        )
        is False
    )


def test_extract_btc_addresses_ignores_hashes_and_random_words():
    text = f"""
    ransom: {BTC_P2PKH} and {BTC_BECH32}
    sha256: {"d" * 64}
    md5: {"a" * 32}
    word: {"a" * 34}
    tampered: {BTC_P2PKH[:-1]}b
    """
    assert ioc_extract.extract_btc_addresses(text) == {BTC_P2PKH, BTC_BECH32}


def test_create_misp_event_object_adds_btc_attribute(monkeypatch):
    mock_event = MagicMock()
    monkeypatch.setattr(ioc_extract, "MISPEvent", MagicMock(return_value=mock_event))
    monkeypatch.setattr(
        ioc_extract, "to_yyyy_mm_dd", MagicMock(return_value="2024-02-03")
    )
    article = {"date": "ignored", "url": "http://source", "content": "body"}

    ioc_extract.create_misp_event_object(
        article, "info", {"btc_addresses": {BTC_P2PKH}}
    )

    mock_event.add_attribute.assert_any_call(
        type="btc", value=BTC_P2PKH, category="Financial fraud", to_ids=False
    )


def test_is_valid_xmr_address_accepts_known_lengths():
    assert len(XMR_ADDRESS) == 95
    assert ioc_extract.is_valid_xmr_address(XMR_ADDRESS) is True
    integrated = "4A" + XMR_ADDRESS[2:] + "1" * 11
    assert len(integrated) == 106
    assert ioc_extract.is_valid_xmr_address(integrated) is True


def test_is_valid_xmr_address_rejects_wrong_shape():
    assert ioc_extract.is_valid_xmr_address(XMR_ADDRESS[:-1]) is False  # 94 chars
    assert ioc_extract.is_valid_xmr_address(XMR_ADDRESS + "A") is False  # 96 chars
    assert ioc_extract.is_valid_xmr_address("5" + XMR_ADDRESS[1:]) is False  # prefix
    assert ioc_extract.is_valid_xmr_address("8C" + XMR_ADDRESS[2:]) is False  # 2nd char
    # 0, O, I and l are not in the base58 alphabet
    assert ioc_extract.is_valid_xmr_address(XMR_ADDRESS[:-1] + "0") is False


def test_extract_xmr_addresses_ignores_adjacent_text():
    text = f"""
    wallet: {XMR_ADDRESS}
    truncated: {XMR_ADDRESS[:-1]}
    glued: prefix{XMR_ADDRESS}
    """
    assert ioc_extract.extract_xmr_addresses(text) == {XMR_ADDRESS}


def test_create_misp_event_object_adds_xmr_attribute(monkeypatch):
    mock_event = MagicMock()
    monkeypatch.setattr(ioc_extract, "MISPEvent", MagicMock(return_value=mock_event))
    monkeypatch.setattr(
        ioc_extract, "to_yyyy_mm_dd", MagicMock(return_value="2024-02-03")
    )
    article = {"date": "ignored", "url": "http://source", "content": "body"}

    ioc_extract.create_misp_event_object(
        article, "info", {"xmr_addresses": {XMR_ADDRESS}}
    )

    mock_event.add_attribute.assert_any_call(
        type="xmr", value=XMR_ADDRESS, category="Financial fraud", to_ids=False
    )


def test_create_misp_event_object_adds_cve_attribute(monkeypatch):
    mock_event = MagicMock()
    monkeypatch.setattr(ioc_extract, "MISPEvent", MagicMock(return_value=mock_event))
    monkeypatch.setattr(
        ioc_extract, "to_yyyy_mm_dd", MagicMock(return_value="2024-02-03")
    )
    article = {"date": "ignored", "url": "http://source", "content": "body"}

    ioc_extract.create_misp_event_object(article, "info", {"cves": {"CVE-2024-3400"}})

    mock_event.add_attribute.assert_any_call(
        type="vulnerability",
        value="CVE-2024-3400",
        category="External analysis",
        to_ids=False,
    )


def test_create_misp_event_object_adds_attributes(monkeypatch):
    mock_event = MagicMock()
    monkeypatch.setattr(ioc_extract, "MISPEvent", MagicMock(return_value=mock_event))
    monkeypatch.setattr(
        ioc_extract, "to_yyyy_mm_dd", MagicMock(return_value="2024-02-03")
    )

    iocs = {
        "urls": {"http://evil.test"},
        "ips": {"203.0.113.5"},
        "fqdns": {"evil.test"},
        "hashes": {"deadbeefdeadbeefdeadbeefdeadbeef", "b" * 40, "c" * 65},
        "browser_extensions": {"a" * 32},
    }
    article = {"date": "ignored", "url": "http://source", "content": "body"}

    event = ioc_extract.create_misp_event_object(article, "info", iocs)

    assert event is mock_event
    mock_event.add_attribute.assert_any_call(
        type="url", value="http://source", category="External analysis", to_ids=False
    )
    mock_event.add_attribute.assert_any_call(
        type="url", value="http://evil.test", category="Network activity", to_ids=True
    )
    mock_event.add_attribute.assert_any_call(
        type="ip-dst", value="203.0.113.5", category="Network activity", to_ids=True
    )
    mock_event.add_attribute.assert_any_call(
        type="hostname", value="evil.test", category="Network activity", to_ids=True
    )
    mock_event.add_attribute.assert_any_call(
        type="md5",
        value="deadbeefdeadbeefdeadbeefdeadbeef",
        category="Network activity",
        to_ids=True,
    )
    mock_event.add_attribute.assert_any_call(
        type="sha1", value="b" * 40, category="Network activity", to_ids=True
    )
    mock_event.add_attribute.assert_any_call(
        type="chrome-extension-id",
        value="a" * 32,
        category="Payload installation",
        to_ids=True,
    )
    # The raw-article "comment" attribute and both AI event_reports are
    # currently commented out in create_misp_event_object (see AGENTS.md).
    # 7 = source url + url + ip + hostname + md5 + sha1 + chrome-extension-id.
    # The 65-char hash has no MISP type and is skipped.
    assert mock_event.add_attribute.call_count == 7


def test_trim_to_ioc_section_cuts_before_heading():
    text = """```markdown
    ### Title
    intro

    ### IoCs
    | Type | Value | Context |
    |---|---|---|
    | File path | C:\\tmp\\evil.exe | dropper |
    ```"""
    trimmed = ioc_extract._trim_to_ioc_section(text)
    assert trimmed.startswith("### IoCs")
    assert "Title" not in trimmed


def test_parse_ioc_rows_filters_and_maps():
    markdown = """### IoCs
    | Type | Value | Context |
    |---|---|---|
    | File path | C:\\tmp\\evil.exe | dropper |
    | Command or process | powershell -enc aaa | persistence |
    | Domain | example.com | skip |
    """
    rows = ioc_extract._parse_ioc_rows_from_markdown(markdown)
    assert rows == [
        {"kind": "file", "value": "C:\\tmp\\evil.exe", "context": "dropper"},
        {
            "kind": "command",
            "value": "powershell -enc aaa",
            "context": "persistence",
        },
    ]


def test_create_misp_event_object_emits_no_ai_reports(monkeypatch):
    """LLM enrichment is intentionally disabled in create_misp_event_object.

    If someone re-enables analyze_threat_article / add_event_report, this test
    fails and forces the AI-path tests (and AGENTS.md) to be updated with it.
    """
    mock_event = MagicMock()
    monkeypatch.setattr(ioc_extract, "MISPEvent", MagicMock(return_value=mock_event))
    monkeypatch.setattr(
        ioc_extract, "to_yyyy_mm_dd", MagicMock(return_value="2024-02-03")
    )

    article = {"date": "ignored", "url": "http://source", "content": "body"}
    iocs = {"urls": set(), "ips": set(), "fqdns": set(), "hashes": set(), "browser_extensions": set()}

    event = ioc_extract.create_misp_event_object(article, "info", iocs)

    assert event is mock_event
    assert not hasattr(ioc_extract, "analyze_threat_article")
    mock_event.add_event_report.assert_not_called()
    mock_event.add_object.assert_not_called()
    mock_event.add_attribute.assert_called_once_with(
        type="url", value="http://source", category="External analysis", to_ids=False
    )


def test_add_ai_iocs_from_summary_trims_quotes(monkeypatch):
    event = MagicMock()
    obj = MagicMock()
    monkeypatch.setattr(ioc_extract, "MISPObject", MagicMock(return_value=obj))
    ai_summary = """### IoCs
    | Type | Value | Context |
    |---|---|---|
    | File path | `'\"C:\\evil\\quoted.exe\"'` | dropper |
    | Command or process | `\"powershell -enc aaa\"` | persistence |
    | Email | '"attacker@example.com"' | sender |
    """

    ioc_extract._add_ai_iocs_from_summary(event, ai_summary)

    obj.add_attribute.assert_called_once_with("command_line", "powershell -enc aaa")
    assert obj.comment == "persistence"
    event.add_object.assert_called_once_with(obj)
    event.add_attribute.assert_any_call(
        category="Persistence mechanism",
        type="filename",
        value="C:\\evil\\quoted.exe",
        comment="dropper",
    )
    event.add_attribute.assert_any_call(
        category="Payload delivery",
        type="email-src",
        value="attacker@example.com",
        comment="sender",
    )


def test_warning_list_filtering_is_enabled_by_default():
    """Writing to MISP keeps the filter: only --no-misp opts out (AGENTS.md §11)."""
    assert ioc_extract.USE_WARNING_LISTS is True


def test_is_suspicious_domain_keeps_listed_domain_when_filtering_disabled(reset_warning_lists):
    reset_warning_lists.search.return_value = "listed"
    assert ioc_extract.is_suspicious_domain("evil.test") is False

    reset_warning_lists.search.reset_mock()
    ioc_extract.set_warning_list_filtering(False)
    assert ioc_extract.is_suspicious_domain("evil.test") is True
    # The COMMON_DOMAINS pass is not warninglist-based and stays in force.
    assert ioc_extract.is_suspicious_domain("google.com") is False
    reset_warning_lists.search.assert_not_called()


def test_is_suspicious_url_keeps_listed_url_when_filtering_disabled(reset_warning_lists):
    reset_warning_lists.search.return_value = "listed"
    assert ioc_extract.is_suspicious_url("http://evil.test/a") is False

    reset_warning_lists.search.reset_mock()
    ioc_extract.set_warning_list_filtering(False)
    assert ioc_extract.is_suspicious_url("http://evil.test/a") is True
    reset_warning_lists.search.assert_not_called()


def test_is_global_ipv4_keeps_cdn_ip_when_filtering_disabled(reset_warning_lists):
    reset_warning_lists.search.return_value = "Cloudflare IP"
    assert ioc_extract.is_global_ipv4("1.1.1.1") is False

    reset_warning_lists.search.reset_mock()
    ioc_extract.set_warning_list_filtering(False)
    assert ioc_extract.is_global_ipv4("1.1.1.1") is True
    # Only the warninglist pass is skipped; private space is still rejected.
    assert ioc_extract.is_global_ipv4("10.0.0.1") is False
    reset_warning_lists.search.assert_not_called()


def test_extract_iocs_keeps_listed_ioc_when_filtering_disabled(reset_warning_lists):
    reset_warning_lists.search.return_value = "listed"
    text = "IOC: hxxp://cdn.evil[.]test/payload.bin"
    filtered = ioc_extract.extract_iocs_from_content(text)
    assert filtered["urls"] == set()
    assert filtered["fqdns"] == set()

    ioc_extract.set_warning_list_filtering(False)
    unfiltered = ioc_extract.extract_iocs_from_content(text)
    assert unfiltered["urls"] == {"http://cdn.evil.test/payload.bin"}
    assert unfiltered["fqdns"] == {"cdn.evil.test"}

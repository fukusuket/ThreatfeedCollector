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


import os
import csv
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Ensure required env vars to avoid exit on import
os.environ.setdefault("MISP_KEY", "dummy")
os.environ.setdefault("DAYS_BACK", "7")

# Add project root to import path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import ioc_collect


@pytest.fixture(autouse=True)
def patch_env(monkeypatch, tmp_path):
    # Ensure DAYS_BACK and OUTPUT_CSV are defined for functions using globals
    monkeypatch.setattr(ioc_collect, "DAYS_BACK", 7)
    monkeypatch.setattr(ioc_collect, "OUTPUT_CSV", str(tmp_path / "stats.csv"))
    # Make MISP URLs harmless
    monkeypatch.setattr(ioc_collect, "MISP_URL", "http://misp.local")
    monkeypatch.setattr(ioc_collect, "MISP_KEY", "dummy")


def test_entry_get_supports_dict_and_obj():
    obj = SimpleNamespace(title="obj")
    assert ioc_collect._entry_get({"title": "dict"}, "title") == "dict"
    assert ioc_collect._entry_get(obj, "title") == "obj"
    assert ioc_collect._entry_get(obj, "missing", "default") == "default"


def test_decode_response_text_prefers_apparent(monkeypatch):
    body = "こんにちは"
    resp = MagicMock()
    resp.encoding = "iso-8859-1"
    resp.apparent_encoding = "utf-8"
    resp.content = body.encode("utf-8")
    assert ioc_collect.decode_response_text(resp) == body


def test_decode_response_text_falls_back_to_text_on_error():
    resp = MagicMock()
    resp.encoding = "x-bad"
    resp.apparent_encoding = None
    resp.content = b"ignored"
    resp.text = "fallback"
    assert ioc_collect.decode_response_text(resp) == "fallback"


def test_response_text_prefers_text():
    resp = MagicMock()
    resp.text = "direct"
    assert ioc_collect.response_text(resp) == "direct"


def test_response_text_uses_decode_when_no_text():
    resp = MagicMock()
    resp.text = None
    resp.encoding = "utf-8"
    resp.apparent_encoding = None
    resp.content = b"abc"
    assert ioc_collect.response_text(resp) == "abc"


def test_is_recent_article_handles_tz_and_empty():
    cutoff = ioc_collect.datetime(2024, 1, 1)
    assert ioc_collect.is_recent_article("2024-01-02T00:00:00+09:00", cutoff) is True
    assert ioc_collect.is_recent_article("2023-12-31", cutoff) is False
    assert ioc_collect.is_recent_article("", cutoff) is True
    assert ioc_collect.is_recent_article("bad-date", cutoff) is True


def test_strip_scripts_and_get_text_removes_scripts():
    class Dummy:
        def __init__(self):
            self.calls = []

        def __call__(self, selectors):
            return []

        def get_text(self, separator="\n"):
            return "ok"

    dummy_soup = Dummy()
    assert ioc_collect.strip_scripts_and_get_text(dummy_soup) == "ok"


def test_fetch_url_content_success(monkeypatch):
    response = MagicMock()
    response.text = "<html><body>hello</body></html>"
    response.raise_for_status.return_value = None
    monkeypatch.setattr(ioc_collect.requests, "get", MagicMock(return_value=response))
    monkeypatch.setattr(
        ioc_collect,
        "BeautifulSoup",
        MagicMock(return_value=MagicMock(get_text=MagicMock(return_value="hello"))),
    )
    assert ioc_collect.fetch_url_content("http://example.com") == "hello"


def test_fetch_url_content_handles_errors(monkeypatch):
    monkeypatch.setattr(
        ioc_collect.requests, "get", MagicMock(side_effect=Exception("boom"))
    )
    assert ioc_collect.fetch_url_content("http://bad") == ""
    assert ioc_collect.fetch_url_content("") == ""


def test_process_feed_builds_articles(monkeypatch):
    entry = {
        "published": "2024-01-02",
        "title": "t",
        "link": "http://x",
        "summary": "<p>sum</p>",
    }
    feed = SimpleNamespace(entries=[entry])
    response = MagicMock(content=b"data", raise_for_status=MagicMock())

    monkeypatch.setattr(ioc_collect.requests, "get", MagicMock(return_value=response))
    monkeypatch.setattr(ioc_collect.feedparser, "parse", MagicMock(return_value=feed))
    monkeypatch.setattr(ioc_collect, "is_recent_article", MagicMock(return_value=True))
    monkeypatch.setattr(
        ioc_collect,
        "BeautifulSoup",
        MagicMock(return_value=MagicMock(get_text=MagicMock(return_value="sum"))),
    )

    result = ioc_collect.process_feed(
        "vendor", "http://feed", ioc_collect.datetime.now()
    )
    assert result == [
        {
            "title": "t",
            "date": "2024-01-02",
            "url": "http://x",
            "content": "sum",
            "vendor": "vendor",
        }
    ]


def test_process_feed_handles_failure(monkeypatch):
    monkeypatch.setattr(
        ioc_collect.requests, "get", MagicMock(side_effect=Exception("boom"))
    )
    assert (
        ioc_collect.process_feed("v", "http://feed", ioc_collect.datetime.now()) == []
    )


def test_fetch_full_content_crawl_links(monkeypatch):
    html_main = "<html><body><a href='http://child'>c</a></body></html>"
    html_child = "<html><title>Child</title><body>body</body></html>"

    def fake_get(url, *args, **kwargs):
        if url == "http://main":
            resp = MagicMock(text=html_main, raise_for_status=MagicMock())
            return resp
        resp = MagicMock(text=html_child, raise_for_status=MagicMock())
        return resp

    def soup_for(text, *_):
        if text == html_main:
            soup = MagicMock()
            link = MagicMock(get=MagicMock(return_value="http://child"))
            soup.find_all.return_value = [link]
            soup.title = MagicMock(string="Main")
            soup.get_text.return_value = "main"
            return soup
        soup = MagicMock()
        soup.find_all.return_value = []
        soup.title = MagicMock(string="Child")
        soup.get_text.return_value = "child"
        return soup

    monkeypatch.setattr(ioc_collect.requests, "get", MagicMock(side_effect=fake_get))
    monkeypatch.setattr(ioc_collect, "BeautifulSoup", MagicMock(side_effect=soup_for))
    monkeypatch.setattr(
        ioc_collect, "strip_scripts_and_get_text", lambda s: s.get_text()
    )
    monkeypatch.setattr(ioc_collect, "to_yyyy_mm_dd", lambda d: "2024-01-01")

    article = {"url": "http://main", "date": "2024-01-01", "vendor": "v", "title": "T"}
    result = ioc_collect.fetch_full_content(article, crawl_links=True)
    assert len(result) == 2
    assert result[0]["content"] == "main"
    assert result[1]["title"] == "Child"
    assert result[1]["url"] == "http://child"


def test_fetch_full_content_handles_errors(monkeypatch):
    monkeypatch.setattr(
        ioc_collect.requests, "get", MagicMock(side_effect=Exception("boom"))
    )
    assert ioc_collect.fetch_full_content({"url": "http://x"}) == []


def test_fetch_full_content_skips_common_domains(monkeypatch):
    html_main = "<a href='http://google.com'></a>"
    resp = MagicMock(text=html_main, raise_for_status=MagicMock())
    monkeypatch.setattr(ioc_collect.requests, "get", MagicMock(return_value=resp))

    soup = MagicMock()
    link = MagicMock(get=MagicMock(return_value="http://google.com"))
    soup.find_all.return_value = [link]
    soup.title = MagicMock(string="Main")
    soup.get_text.return_value = "main"
    monkeypatch.setattr(ioc_collect, "BeautifulSoup", MagicMock(return_value=soup))
    monkeypatch.setattr(
        ioc_collect, "strip_scripts_and_get_text", lambda s: s.get_text()
    )

    article = {"url": "http://main", "date": "2024-01-01", "vendor": "v", "title": "T"}
    result = ioc_collect.fetch_full_content(article, crawl_links=True)
    assert len(result) == 1  # child skipped


def test_add_event_to_misp_skips_existing(monkeypatch):
    misp = MagicMock()
    misp.search.side_effect = [[1], []]  # first call finds event by title
    assert (
        ioc_collect.add_event_to_misp(
            {"title": "t", "vendor": "v", "url": "u"}, {"urls": set()}, misp
        )
        is False
    )


def test_add_event_to_misp_creates(monkeypatch):
    misp = MagicMock()
    misp.search.side_effect = [[], []]
    event_obj = object()
    monkeypatch.setattr(
        ioc_collect, "create_misp_event_object", MagicMock(return_value=event_obj)
    )
    assert (
        ioc_collect.add_event_to_misp(
            {"title": "t", "vendor": "v", "url": "u"}, {"urls": {"u"}}, misp
        )
        is True
    )
    misp.add_event.assert_called_once_with(event_obj, pythonify=True)


def test_process_article_skips_existing_attr(monkeypatch):
    misp = MagicMock()
    misp.search.side_effect = [["hit"], []]  # first URL check hits
    monkeypatch.setattr(
        ioc_collect,
        "fetch_full_content",
        MagicMock(return_value=[{"url": "u", "content": ""}]),
    )
    assert ioc_collect.process_article(misp, {"url": "u", "title": "t"}, "v") is False


def test_process_article_creates_when_iocs(monkeypatch):
    misp = MagicMock()
    misp.search.return_value = []
    monkeypatch.setattr(
        ioc_collect,
        "fetch_full_content",
        MagicMock(return_value=[{"url": "u", "content": "body"}]),
    )
    monkeypatch.setattr(
        ioc_collect,
        "extract_iocs_from_content",
        MagicMock(
            return_value={
                "urls": {"a", "b"},
                "ips": {"c"},
                "hashes": set(),
                "fqdns": set(),
                "browser_extensions": set(),
            }
        ),
    )
    monkeypatch.setattr(ioc_collect, "add_event_to_misp", MagicMock(return_value=True))
    assert ioc_collect.process_article(misp, {"url": "u", "title": "t"}, "v") is True


def test_process_article_needs_enough_iocs(monkeypatch):
    misp = MagicMock()
    misp.search.return_value = []
    monkeypatch.setattr(
        ioc_collect,
        "fetch_full_content",
        MagicMock(return_value=[{"url": "u", "content": "body"}]),
    )
    monkeypatch.setattr(
        ioc_collect,
        "extract_iocs_from_content",
        MagicMock(
            return_value={
                "urls": {"a"},
                "ips": set(),
                "hashes": {"h"},
                "fqdns": set(),
                "browser_extensions": set(),
            }
        ),
    )
    assert ioc_collect.process_article(misp, {"url": "u", "title": "t"}, "v") is False


def test_save_stats_writes_csv(monkeypatch, tmp_path):
    event = SimpleNamespace(
        info="[v] title",
        date="2024-01-02",
        attributes=[
            SimpleNamespace(category="Other", type="text", value="x"),
            SimpleNamespace(
                category="External analysis", type="url", value="http://blog"
            ),
        ],
    )
    misp = MagicMock()
    misp.search.return_value = [event]
    monkeypatch.setattr(ioc_collect, "OUTPUT_CSV", str(tmp_path / "out.csv"))
    monkeypatch.setattr(ioc_collect, "DAYS_BACK", 7)

    ioc_collect.save_stats(misp)

    rows = list(csv.DictReader(Path(ioc_collect.OUTPUT_CSV).read_text().splitlines()))
    assert rows == [
        {
            "date": "2024-01-02",
            "vendor": "v",
            "iocs": "1",
            "title": "title",
            "blog url": "http://blog",
        }
    ]


def test_save_stats_handles_error(monkeypatch, caplog):
    misp = MagicMock()
    misp.search.side_effect = Exception("boom")
    monkeypatch.setattr(ioc_collect, "OUTPUT_CSV", str(Path("/nonexistent/out.csv")))
    ioc_collect.save_stats(misp)
    assert any("Failed to save stats" in rec.message for rec in caplog.records)


def test_main_handles_misp_failure(monkeypatch):
    monkeypatch.setattr(ioc_collect, "PyMISP", MagicMock(side_effect=Exception("fail")))
    with pytest.raises(SystemExit):
        ioc_collect.main()


def test_main_handles_missing_rss(monkeypatch, tmp_path):
    monkeypatch.setattr(ioc_collect, "PyMISP", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(ioc_collect, "RSS_FEEDS_CSV", str(tmp_path / "missing.csv"))
    with pytest.raises(SystemExit):
        ioc_collect.main()


def test_main_happy_path(monkeypatch, tmp_path):
    monkeypatch.setattr(ioc_collect, "PyMISP", MagicMock(return_value=MagicMock()))
    feeds = tmp_path / "feeds.csv"
    feeds.write_text("vendor,feed,blog,crawl\nv,http://feed,http://blog,False\n")
    monkeypatch.setattr(ioc_collect, "RSS_FEEDS_CSV", str(feeds))

    monkeypatch.setattr(
        ioc_collect,
        "process_feed",
        MagicMock(
            return_value=[
                {
                    "title": "t",
                    "date": "2024-01-01",
                    "url": "u",
                    "content": "c",
                    "vendor": "v",
                }
            ]
        ),
    )
    monkeypatch.setattr(ioc_collect, "process_article", MagicMock())
    monkeypatch.setattr(ioc_collect, "save_stats", MagicMock())

    ioc_collect.main()
    ioc_collect.process_article.assert_called()
    ioc_collect.save_stats.assert_called()

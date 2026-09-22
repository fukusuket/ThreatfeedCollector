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
    assert len(result) == 1
    assert result[0]["title"] == "Child"
    assert result[0]["url"] == "http://child"


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
    assert len(result) == 0  # child skipped


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


def test_process_article_ignores_non_trigger_ioc_kinds(monkeypatch):
    """Only network IoC kinds may trigger event creation.

    Context IoCs (CVE, wallet addresses, ...) are written to the event but must
    never create one on their own, however many of them an article contains.
    """
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
                "hashes": set(),
                "fqdns": set(),
                "browser_extensions": set(),
                "cves": {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
                "btc_addresses": {"addr1", "addr2"},
            }
        ),
    )
    monkeypatch.setattr(ioc_collect, "add_event_to_misp", MagicMock(return_value=True))
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


def test_main_accepts_three_column_feed_row(monkeypatch, tmp_path):
    """README documents a 3-column feeds.csv and the reader accepts len(row) >= 2.

    Rows narrower than 4 columns must not blow up the vendor worker (the
    failure is swallowed by main's per-vendor except, so the symptom is a
    silently skipped feed).
    """
    monkeypatch.setattr(ioc_collect, "PyMISP", MagicMock(return_value=MagicMock()))
    feeds = tmp_path / "feeds.csv"
    feeds.write_text("Vendor,RSS,Blog\nv,http://feed,http://blog\n")
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
    # 4th column absent -> link crawling stays off
    assert ioc_collect.process_article.call_args[0][3] is False


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


# --- --no-misp (local) mode -------------------------------------------------

LOCAL_ARTICLE = {
    "title": "t",
    "date": "2024-01-02",
    "url": "http://blog/post#frag",
    "content": "body",
    "vendor": "v",
}
# Three trigger IoCs -> one event / one stats row.
LOCAL_IOCS = {
    "urls": {"http://a.example", "http://b.example"},
    "ips": {"1.2.3.4"},
    "hashes": set(),
    "fqdns": set(),
    "browser_extensions": set(),
}


def _local_row(monkeypatch, article=None, iocs=None):
    monkeypatch.setattr(
        ioc_collect,
        "fetch_full_content",
        MagicMock(return_value=[dict(article or LOCAL_ARTICLE)]),
    )
    monkeypatch.setattr(
        ioc_collect,
        "extract_iocs_from_content",
        MagicMock(return_value=dict(iocs if iocs is not None else LOCAL_IOCS)),
    )
    rows = []
    created = ioc_collect.process_article(
        None, dict(article or LOCAL_ARTICLE), "v", stats=rows
    )
    return created, rows


def test_process_article_local_mode_appends_row(monkeypatch):
    created, rows = _local_row(monkeypatch)
    assert created is True
    assert len(rows) == 1
    row = rows[0]
    assert str(row["date"]) == "2024-01-02"
    assert row["vendor"] == "v"
    # iocs excludes the External analysis url attribute: 2 urls + 1 ip
    assert row["iocs"] == 3
    assert row["title"] == "t"
    # the url fragment is stripped, as on the MISP path
    assert row["blog url"] == "http://blog/post"


def test_process_article_local_mode_never_touches_misp(monkeypatch):
    add_event = MagicMock()
    monkeypatch.setattr(ioc_collect, "add_event_to_misp", add_event)
    created, rows = _local_row(monkeypatch)
    assert created is True
    assert rows
    add_event.assert_not_called()


def test_process_article_local_mode_respects_trigger_threshold(monkeypatch):
    """Two trigger IoCs are not enough, and non-trigger kinds do not make up the
    difference -- the article must produce no row at all."""
    created, rows = _local_row(
        monkeypatch,
        iocs={
            "urls": {"http://a.example"},
            "ips": {"1.2.3.4"},
            "hashes": {"d41d8cd98f00b204e9800998ecf8427e"},
            "fqdns": set(),
            "browser_extensions": set(),
        },
    )
    assert created is False
    assert rows == []


def test_local_row_matches_misp_row(monkeypatch):
    """The CSV must not change meaning depending on the mode: the row built
    locally has to equal the row save_stats would derive from the pushed event."""
    misp = MagicMock()
    misp.search.return_value = []
    assert (
        ioc_collect.add_event_to_misp(dict(LOCAL_ARTICLE), dict(LOCAL_IOCS), misp)
        is True
    )
    pushed_event = misp.add_event.call_args[0][0]
    misp_rows = ioc_collect.stats_rows_from_events([pushed_event])

    local_event = ioc_collect.build_event(dict(LOCAL_ARTICLE), dict(LOCAL_IOCS))
    local_rows = ioc_collect.stats_rows_from_events([local_event])

    assert local_rows == misp_rows


def test_local_row_title_truncated_to_100_chars(monkeypatch):
    article = dict(LOCAL_ARTICLE, title="x" * 150)
    _, rows = _local_row(monkeypatch, article=article)
    assert rows[0]["title"] == "x" * 100


def test_merge_stats_rows_prefers_existing():
    existing = [
        {"date": "d1", "vendor": "v", "iocs": "1", "title": "old", "blog url": "u1"}
    ]
    new = [
        {"date": "d2", "vendor": "v", "iocs": 9, "title": "new", "blog url": "u1"},
        {"date": "d3", "vendor": "v", "iocs": 2, "title": "fresh", "blog url": "u2"},
    ]
    merged = ioc_collect.merge_stats_rows(existing, new)
    assert [row["title"] for row in merged] == ["old", "fresh"]


def test_save_stats_local_merges_existing_csv(monkeypatch, tmp_path):
    out = tmp_path / "out.csv"
    monkeypatch.setattr(ioc_collect, "OUTPUT_CSV", str(out))
    row_a = {
        "date": "2024-01-02",
        "vendor": "v",
        "iocs": 3,
        "title": "a",
        "blog url": "http://blog/a",
    }
    row_b = dict(row_a, title="b", blog_url=None)
    row_b.pop("blog_url")
    row_b["blog url"] = "http://blog/b"

    ioc_collect.save_stats_local([row_a])
    # same-day re-run must not duplicate the article already recorded
    ioc_collect.save_stats_local([row_a, row_b])

    rows = list(csv.DictReader(out.read_text().splitlines()))
    assert [row["blog url"] for row in rows] == ["http://blog/a", "http://blog/b"]
    assert [row["title"] for row in rows] == ["a", "b"]


def _no_misp_feeds(monkeypatch, tmp_path):
    feeds = tmp_path / "feeds.csv"
    feeds.write_text("Vendor,RSS,Blog\nv,http://feed,http://blog\n")
    monkeypatch.setattr(ioc_collect, "RSS_FEEDS_CSV", str(feeds))
    monkeypatch.setattr(
        ioc_collect, "process_feed", MagicMock(return_value=[dict(LOCAL_ARTICLE)])
    )


def test_main_no_misp_never_connects(monkeypatch, tmp_path):
    """--no-misp must not construct PyMISP, and must not need MISP_KEY."""
    pymisp = MagicMock()
    monkeypatch.setattr(ioc_collect, "PyMISP", pymisp)
    monkeypatch.setattr(ioc_collect, "MISP_KEY", "")
    _no_misp_feeds(monkeypatch, tmp_path)
    monkeypatch.setattr(ioc_collect, "process_article", MagicMock(return_value=False))
    save_stats = MagicMock()
    save_stats_local = MagicMock()
    monkeypatch.setattr(ioc_collect, "save_stats", save_stats)
    monkeypatch.setattr(ioc_collect, "save_stats_local", save_stats_local)

    ioc_collect.main(["--no-misp"])

    pymisp.assert_not_called()
    save_stats.assert_not_called()
    save_stats_local.assert_called_once()
    assert ioc_collect.process_article.call_args[0][0] is None


def test_main_no_misp_collects_rows_from_workers(monkeypatch, tmp_path):
    monkeypatch.setattr(ioc_collect, "PyMISP", MagicMock())
    _no_misp_feeds(monkeypatch, tmp_path)

    def fake_process_article(
        misp, article, vendor, crawl_links=False, crawl_same_domain=False, stats=None
    ):
        stats.append(
            {
                "date": "2024-01-02",
                "vendor": vendor,
                "iocs": 3,
                "title": "t",
                "blog url": f"http://blog/{vendor}",
            }
        )
        return True

    monkeypatch.setattr(ioc_collect, "process_article", fake_process_article)
    captured = []
    monkeypatch.setattr(
        ioc_collect, "save_stats_local", lambda rows: captured.extend(rows)
    )

    ioc_collect.main(["--no-misp"])

    assert [row["blog url"] for row in captured] == ["http://blog/v"]


def test_save_stats_local_survives_malformed_existing_csv(monkeypatch, tmp_path, caplog):
    """A hand-edited or truncated CSV must not make a successful write report a
    failure, and must not drop the rows from this run."""
    out = tmp_path / "out.csv"
    out.write_text(
        "date,vendor,iocs,title,blog url\n2024-01-01,v,not-a-number,old,http://blog/a\n"
    )
    monkeypatch.setattr(ioc_collect, "OUTPUT_CSV", str(out))

    ioc_collect.save_stats_local(
        [
            {
                "date": "2024-01-02",
                "vendor": "v",
                "iocs": 3,
                "title": "new",
                "blog url": "http://blog/b",
            }
        ]
    )

    rows = list(csv.DictReader(out.read_text().splitlines()))
    assert [row["blog url"] for row in rows] == ["http://blog/a", "http://blog/b"]
    assert not any("Failed to save stats" in rec.message for rec in caplog.records)

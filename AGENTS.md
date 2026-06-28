# AGENTS.md — ThreatfeedCollector

## Overview
Three-module pipeline:
1. **`ioc_collect.py`** — Reads `config/rss_feeds.csv`, fetches RSS feeds in parallel (`ThreadPoolExecutor`), scrapes article HTML, and pushes MISP events.
2. **`ioc_extract.py`** — Extracts IoCs (URLs, IPs, FQDNs, hashes, browser extension IDs) using `iocextract` + `pymispwarninglists`, then builds `MISPEvent` objects with AI-generated reports.
3. **`thunt_advisor.py`** — Generates two `event_report`s per MISP event using `config/prompt-hunt.md` (English analysis) then `config/prompt-translate.md` (Japanese translation). The LLM backend is selected by `LLM_PROVIDER` (`openai` | `bedrock`): OpenAI via the OpenAI SDK, or Claude on AWS Bedrock via `boto3`'s `bedrock-runtime` `invoke_model` (Anthropic Messages API body, `anthropic_version: bedrock-2023-05-31`). Provider SDKs are imported lazily inside `_call_openai` / `_call_bedrock`; model defaults resolve in `_resolve_model` (`OPENAI_MODEL`→`gpt-5.5`, `BEDROCK_MODEL_ID`→`anthropic.claude-opus-4-8`).

## Environment Setup
```bash
./setup.sh          # creates .venv and installs requirements.txt
source .venv/bin/activate
cp .env.example .env   # fill in LLM_PROVIDER, OPENAI_API_KEY or AWS_REGION/BEDROCK_MODEL_ID, MISP_URL, MISP_KEY, DAYS_BACK
python ioc_collect.py
```
No shell exports needed — all env vars are loaded via `python-dotenv` from `.env` (or `../.env`).

## Running Tests
```bash
pytest tests/
```
Tests use `monkeypatch` to stub `iocextract`, `PyMISP`, `WARNING_LISTS`, and the LLM providers (OpenAI / Bedrock) — never require live services. `tests/test_thunt_advisor.py` injects fake `openai` / `boto3` modules to cover both provider paths.  
Set `MISP_KEY=dummy` before import if running tests outside pytest (the module exits on missing key).

## Key Config Files
| File | Purpose |
|---|---|
| `config/rss_feeds.csv` | `Vendor, RSS URL, Blog URL, Crawl links` — `True` in col 4 enables deep link crawling |
| `config/common_domains.txt` | Lowercase domain allowlist; loaded at import into `COMMON_DOMAINS` set |
| `config/suspicious_extensions.txt` | File extensions that invalidate a URL (e.g. `.exe`, `.zip`) |
| `config/prompt-hunt.md` | Jinja-style template with `{{CONTENT}}`, `{{ARTICLE_TITLE}}`, `{{ARTICLE_URL}}`, `{{LANG}}`, `{{ADDITIONAL_PRE_CONTEXT}}` |
| `config/prompt-translate.md` | Same template shape; receives the English AI summary as `{{CONTENT}}` for translation |

## IoC Extraction Conventions
- **Defanged IoCs only** (`[.]`, `hxxp`, `[://]`) are extracted from article text for URLs/IPs; hashes and browser extension IDs are scanned from full text.
- Filtering order: `COMMON_DOMAINS` → `pymispwarninglists` (slow_search) → `ipaddress.is_global` → named CDN/DNS warning list strings.
- Browser extension IDs match regex `[a-p]{32}` (Chrome extension format).
- MISP event is only created when `non-hash IoC count > 2` (see `process_article`).
- Duplicate detection: checks both event title and `External analysis` URL attribute before creating.

## MISP Event Structure
Each event contains:
- `External analysis / url` — source article URL (fragment stripped)
- `Other / comment` — raw article text
- Per-IoC attributes (`Network activity`) + `chrome-extension-id` (`Payload installation`)
- AI IoCs from markdown table in prompt response: `file`→`filename`, `command`→`MISPObject("command-line")`, `registry`→`regkey`, `email`→`email-src`
- Two `event_report`s: `[en]_<title>` and `[jp]_<title>`, distribution=0

## Data Flow
```
rss_feeds.csv → process_feed() → fetch_full_content() [optional crawl]
  → extract_iocs_from_content()
  → analyze_threat_article() ×2 (EN + JP)
  → create_misp_event_object() → misp.add_event()
  → save_stats() → ioc_stats_YYYYMMDD.csv
```

## Parallelism
Feeds are processed concurrently with `FEED_WORKERS` threads (default 8, env-configurable). Each vendor's articles are processed sequentially within its thread.


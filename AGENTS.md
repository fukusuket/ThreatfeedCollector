# AGENTS.md — ThreatfeedCollector

This file is the **single source of truth** for this repository.
Claude Code's loop-operation rules live in `CLAUDE.md`. Facts here, method there — do not duplicate content between them.

---

## 1. What this is

A pipeline that ingests untrusted external web content (vendor threat-intel blog RSS), extracts IoCs, and creates MISP events.
**The whole design assumes its input is text an attacker can influence.**

| Module | Role |
|---|---|
| `ioc_collect.py` | Entry point. Reads `config/rss_feeds.csv`, fetches feeds in parallel (`ThreadPoolExecutor`), scrapes article HTML, pushes to MISP, writes `ioc_stats_YYYYMMDD.csv` |
| `ioc_extract.py` | Extracts IoCs (URL / IP / FQDN / hash / Chrome extension ID / CVE / onion address / BTC address) and builds the `MISPEvent` |
| `thunt_advisor.py` | LLM calls, dispatched on `LLM_PROVIDER` (`openai` \| `bedrock`). **Intentionally not wired into the pipeline — see §5** |
| `app.py` | Streamlit dashboard listing MISP events |

Data flow, with trust labels:

```
rss_feeds.csv [trusted]
  → process_feed() ────────────── everything below is UNTRUSTED
  → fetch_full_content()          external HTML, including crawled links
  → extract_iocs_from_content()   parsing untrusted text
  → analyze_threat_article()      untrusted text enters an LLM prompt  ★injection boundary
  → create_misp_event_object()
  → misp.add_event()              untrusted-derived values are persisted to MISP
  → app.py st.markdown()          untrusted-derived values are rendered in the UI  ★output boundary
```

---

## 2. Setup

```bash
./setup.sh                # creates venv and installs requirements.txt
source venv/bin/activate  # note: setup.sh creates venv/, not .venv/
cp .env.example .env      # fill in values
```

All environment variables are loaded by `python-dotenv` from `.env` (falling back to `../.env`). No shell exports needed.
Required: `MISP_URL`, `MISP_KEY`. LLM work additionally needs `LLM_PROVIDER` and the matching credential.

---

## 3. Verification gates

**"It should work" is not a result.** A change is only done once all four gates have been *run* and their outcome reported.
Each gate yields a verdict from a single command.

```bash
# Gate 1 — Lint (must be clean)
python3 -m ruff check .

# Gate 2 — Unit tests (must be 65 passed)
python3 -m pytest -q

# Gate 3 — Security invariant counts (must match the §4 baseline)
grep -rn "verify=False" *.py | wc -l                       # expected: 6
grep -rn "unsafe_allow_html=True" *.py | wc -l              # expected: 1 (static CSS only)
grep -rnE "ssl=False|PyMISP\([^)]*, *False" *.py | wc -l    # expected: 2

# Gate 4 — Secret leak check (mandatory before any commit)
git diff --cached | grep -nEi "(api[_-]?key|secret|token|authkey|BEARER)\s*[:=]\s*[\"']?[A-Za-z0-9/+_-]{16,}"
# Must produce no output. If it hits, do not commit.
```

### Verification independence

- Write tests **from the spec**, not by transcribing the implementation. A test whose expected values were read off the code just pins the bug in place.
- **Never add a test that touches the network, MISP, or an LLM.** Existing tests stub `iocextract` / `PyMISP` / `WARNING_LISTS` / `openai` / `boto3` via `monkeypatch`. Keep it that way.
- Running a module outside pytest requires `MISP_KEY=dummy` before import (`ioc_collect` calls `sys.exit(1)` without it).
- When touching IoC extraction or filtering, **add cases for input that must be excluded**, not just input that must match. Exclusion logic that has no exclusion test stays green when it breaks.
- A bug fix needs a test that **fails on the old code**. Prove it: revert the fix, watch the test go red, restore. Otherwise you have not verified anything.

---

## 4. Security invariants

These are baselines, not endorsements: "this is how it is today — do not make it worse."
**Do not raise these counts.** Lowering them is welcome, but as a standalone change.

| # | Invariant | Current state |
|---|---|---|
| I1 | Do not add **new** TLS-verification bypasses | `verify=False` ×6 (4 requests calls in `ioc_collect.py`, 2 httpx clients in `thunt_advisor.py`), `PyMISP(..., ssl=False)` ×2 (`ioc_collect.py`, `app.py`). Known debt — see §6 |
| I2 | Never route untrusted data through `unsafe_allow_html=True` | The one call site (`app.py`) passes static CSS only. Passing feed/LLM/MISP-derived strings is forbidden |
| I3 | Never leak secrets to logs, exceptions, or commits | `OPENAI_API_KEY` / `AWS_BEARER_TOKEN_BEDROCK` / `MISP_KEY`. `thunt_advisor.py` logs only payload sizes, never key material. Preserve that |
| I4 | Never let untrusted data act as an LLM **instruction** | `{{CONTENT}}` in `config/prompt-hunt.md` receives raw external HTML. Keep it positioned after the system instructions and clearly framed as data; do not move it when editing the template |
| I5 | Do not trust LLM output | `_parse_ioc_rows_from_markdown` turns model output into MISP attributes. Validate values before they reach MISP, and defang on display (`app.py:defang`) |
| I6 | Do not widen the crawler | `fetch_full_content` follows `<a href>` from fetched pages (`max_links=30`). Do not add anything that permits reaching internal networks or private IPs (no guard today — §6) |
| I7 | Declare and pin dependencies | No import may be missing from `requirements.txt`. Pin every new addition |

---

## 5. Deliberate design decisions (not bugs — do not "fix" them)

**LLM enrichment in `ioc_extract.py` is commented out on purpose.**
The `from thunt_advisor import analyze_threat_article` line, both `analyze_threat_article` calls, the two `add_event_report` calls, and the `_add_ai_iocs_from_summary` call in `create_misp_event_object` are all disabled. So is the `Other / comment` attribute carrying the raw article body.

Consequences to keep in mind:

- `thunt_advisor.py` is maintained and unit-tested, but nothing in the pipeline calls it.
- `_add_ai_iocs_from_summary`, `_trim_to_ioc_section`, and `_parse_ioc_rows_from_markdown` are still live and still tested directly.
- `tests/test_ioc_extract.py::test_create_misp_event_object_emits_no_ai_reports` pins this state. If you re-enable the LLM path, that test fails by design — update it, the AI-path tests, and this section together.
- Events therefore carry the source URL plus extracted IoC attributes, and no event reports.

`ioc_collect.py` also falls back to reading `MISP_KEY` from `/shared/authkey.txt` when the env var is unset. That is a container-deployment affordance; confirm with operations before changing it.

---

## 6. Known debt (do not fix casually; fix only as a standalone change)

- **TLS verification disabled (I1).** A MITM on a threat feed lets an attacker substitute the IoCs, which is a real risk. But this is almost certainly there to accommodate a self-signed internal MISP certificate, and removing it requires deciding how to distribute a CA bundle. **Flipping to `verify=True` "because it is more secure" will break production.** Propose it separately, with a rationale and a migration path.
- **SSRF (I6).** `fetch_full_content` does not validate crawl targets; a link resolving to a private IP is fetched. A fix is welcome, but only with tests showing existing crawl targets still work.
- **Unpinned dependencies.** `requests`, `python-dateutil`, `pymispwarninglists`, `openai`, `boto3`, `python-dotenv`, `pytest`, `ruff`, and `streamlit` float. Pinning them is a supply-chain improvement, and a separate change.
- **CI gaps.** `.github/workflows/test.yml` runs `pytest` only — no ruff, no dependency audit, no secret scan. Gates 1, 3, and 4 are currently manual.
- **`WarningLists(slow_search=True)`** loads heavily at import. Tests must always stub it.

---

## 7. Decisions that are not yours to make

Stop and ask before doing any of these:

- Re-enabling the LLM path in `ioc_extract.py` (§5)
- Changing how `verify=False` / `ssl=False` are handled (§6)
- Adding or removing entries in `config/rss_feeds.csv` — changing what is ingested is an operational change
- Changing the output format of `config/prompt-hunt.md` or `prompt-translate.md`; they are coupled to the parser in `ioc_extract.py`, so changing one side alone breaks the other silently
- Changing the type or category of attributes written to MISP (consistency with existing events)

---

## 8. Config files

| File | Purpose |
|---|---|
| `config/rss_feeds.csv` | `Vendor, RSS URL, Blog URL, Crawl links` — `True` in column 4 enables deep link crawling. Rows with 2 or 3 columns are accepted; missing columns default to empty. `#` starts a comment |
| `config/common_domains.txt` | Lowercase domain exclusion list, loaded into `COMMON_DOMAINS` at import |
| `config/suspicious_extensions.txt` | URLs whose host part ends in one of these are rejected |
| `config/prompt-hunt.md` | Template substituting `{{CONTENT}}` `{{ARTICLE_TITLE}}` `{{ARTICLE_URL}}` `{{LANG}}` `{{ADDITIONAL_PRE_CONTEXT}}` |
| `config/prompt-translate.md` | Same shape; receives the English summary as `{{CONTENT}}` |

---

## 9. Code conventions

- Python 3.12+ (CI runs 3.14; local is 3.13.2). `ruff` is the only linter/formatter.
- Log with `logging` f-strings. **Before logging a value, ask whether it is untrusted data or a secret.**
- Wrap every external I/O in `try/except` and skip the single failing item rather than halting the pipeline. This is a consistent, deliberate pattern across the codebase.
- Add type hints in the style of the surrounding code.

---

## 10. IoC extraction spec (changes require tests)

- Only **defanged** IoCs (`[.]`, `hxxp`, `[://]`) are extracted as URLs/IPs. Hashes and Chrome extension IDs are scanned from the full text.
- Filter order: `COMMON_DOMAINS` → `pymispwarninglists` (slow_search) → `ipaddress.is_global` → CDN/DNS warning-list name matching.
- Chrome extension IDs match `[a-p]{32}`.
- CVE IDs match `CVE-(19|20)\d{2}-\d{4,7}` (case-insensitive, normalized to upper case) and are scanned from the full text. They are written as `vulnerability` / `External analysis` / `to_ids=False`.
- v3 onion addresses are accepted only when the embedded ed25519 checksum verifies (`is_valid_onion_v3`); `[.]onion` defanging is refanged first, and v2 (16-char) addresses are rejected. Written as `onion-address` / `Network activity` / `to_ids=True`.
- Bitcoin addresses are accepted only when their checksum verifies (`is_valid_btc_address`): Base58Check with a mainnet version byte (`0x00`/`0x05`), or bech32/bech32m with the BIP-173/BIP-350 polymod for the witness version. Testnet and mixed-case bech32 are rejected. Written as `btc` / `Financial fraud` / `to_ids=False`.
- A MISP event is created only when the count of IoCs in `EVENT_TRIGGER_IOC_KEYS` (`urls`, `ips`, `fqdns`, `browser_extensions`) is **> 2** (`process_article`). Other kinds are written to the event but never trigger its creation.
- Duplicate detection checks both the event title and the `External analysis` url attribute.

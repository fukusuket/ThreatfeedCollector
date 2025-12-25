# Threat feed Collector

A Python tool that extracts Indicators of Compromise (IoCs) from RSS threat intelligence feeds and creates events in MISP (Malware Information Sharing Platform).

## Features

- Fetches threat intelligence from RSS feeds
- Extracts IoCs (URLs, IPs, FQDNs, hashes) from feed content
- Filters out private IPs and common domains
- Creates MISP events for detected threats
- Generates CSV statistics report

## Requirements

- Python 3.12+
- MISP instance (for event creation)
- MISP API key

## Installation

1. Clone this repository
2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

Alternatively, install manually:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Create a local `.env` from the sample and fill in your credentials/URLs:

```bash
cp .env.example .env
```

Then edit `.env` to set:

```dotenv
OPENAI_API_KEY=your-openai-key
MISP_URL=https://your-misp-instance.com
MISP_KEY=your_misp_api_key
DAYS_BACK=1
```

These values are read by the app at runtime; no shell exports are required.

## RSS Feeds Configuration

Create a `rss_feeds.csv` file with your threat intelligence feeds:

```csv
Vendor, RSS Feed URL, Blog URL
Sample vendor,https://example.com/feed/,https://example.com/
```

Lines starting with `#` are treated as comments.

## Usage

```bash
source venv/bin/activate
python3 ioc_collect.py
```

The tool will:
1. Read RSS feeds from the CSV file
2. Extract recent articles (based on `DAYS_BACK`)
3. Extract IoCs from article content
4. Create MISP events for articles containing IoCs
5. Generate a statistics CSV report

## Related Projects
- [THuntLab](https://github.com/fukusuket/THuntLab)

## Output

- **MISP Events**: Created automatically in your MISP instance
- **Statistics CSV**: Contains IoC counts and events created per vendor

## IoC Types Detected

- **URLs**: HTTP/HTTPS URLs (excluding common domains)
- **IP Addresses**: Public IPv4 addresses
- **FQDNs**: Domain names (excluding common domains)
- **Hashes**: MD5, SHA-1, and SHA-256 hashes

## Acknowledgements
- [MISP/PyMISP](https://github.com/MISP/PyMISP)
- [MISP/PyMISPWarningLists](https://github.com/MISP/PyMISPWarningLists.git)
- [kurtmckee/feedparser](https://github.com/kurtmckee/feedparser)
- [InQuest/iocextract](https://github.com/InQuest/iocextract)
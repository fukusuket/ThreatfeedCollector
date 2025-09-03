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

Set the following environment variables:

```bash
export MISP_URL="https://your-misp-instance.com"
export MISP_KEY="your_misp_api_key"
export RSS_FEEDS_CSV="rss_feeds.csv"
export DAYS_BACK="1"
export OUTPUT_CSV="ioc_stats_$(date +%Y%m%d).csv"
```

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
python3 cti.py
```

The tool will:
1. Read RSS feeds from the CSV file
2. Extract recent articles (based on `DAYS_BACK`)
3. Extract IoCs from article content
4. Create MISP events for articles containing IoCs
5. Generate a statistics CSV report

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
- [kurtmckee/feedparser](https://github.com/kurtmckee/feedparser)
- [InQuest/iocextract](https://github.com/InQuest/iocextract)
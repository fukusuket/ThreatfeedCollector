from pathlib import Path

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from pymisp import PyMISP
from dotenv import load_dotenv
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
env_path = Path(__file__).resolve().parent / ".env"
if not env_path.exists():
    env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)


MISP_URL = os.getenv("MISP_URL", "")
MISP_KEY = os.getenv("MISP_KEY", "")

font_css = """
<style>
    .stMarkdown p, .stMarkdown li, .stMarkdown span{
        font-size: 14px !important;
    }
    .stMarkdown table th, .stMarkdown table td {
        font-size: 14px !important;
    }
    .stMarkdown h3 {
        font-size: 18px !important;
    }
    .stMarkdown code {
        font-size: 14px !important;
    }
</style>
"""

st.markdown(font_css, unsafe_allow_html=True)
st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")

def defang(value: str) -> str:
    """Neutralize dangerous IOCs (url/ip/domain) for safe display."""
    return value.replace("http", "hxxp").replace(".", "[.]")

end_date = datetime.now().date()
start_date = end_date - timedelta(days=5)
date_range = st.date_input(
    "Date range",
    (start_date, end_date),
    key="hunt_date_range",
    label_visibility="collapsed",
)

if isinstance(date_range, tuple) and len(date_range) == 2:
    start_date, end_date = date_range


misp = PyMISP(MISP_URL, MISP_KEY, False)
events = misp.search('events', date_to=end_date.strftime('%Y-%m-%d'), date_from=start_date.strftime('%Y-%m-%d'))
if not events:
    st.info("No Event found for the selected date range.")
else:
    events = sorted(events, key=lambda e: e['Event']['date'], reverse=True)
    for event in events:
        try:
            title = event['Event']['info']
            label = f"{event['Event']['date']} | {title}"
            attributes = event['Event'].get('Attribute', [])

            article_url = next(
                (
                    attr['value']
                    for attr in attributes
                    if attr.get('category') == "External analysis" and attr.get('type') == "url"
                ),
                None,
            )

            md_lines = [f"### [{title}]({article_url})", ""]
            md_lines.append("| Category | Type | Value |")
            md_lines.append("| --- | --- | --- |")
            for attr in attributes:
                category = attr.get('category', '')
                attr_type = attr.get('type', '')
                value = str(attr.get('value', ''))
                # Defang risky IOCs (url/ip/domain) except the External analysis URL.
                is_external_url = category == "External analysis" and attr_type == "url"
                if is_external_url:
                    continue
                if not is_external_url and any(
                    kw in attr_type for kw in ("url", "ip", "domain", "hostname")
                ):
                    value = defang(value)
                value = value.replace("|", "\\|")
                md_lines.append(
                    f"| {category} | {attr_type} | {value} |"
                )

            with st.expander(label, expanded=False):
                st.markdown("\n".join(md_lines))
        except Exception as e:
            st.warning(f"Failed to read {event}: {e}")

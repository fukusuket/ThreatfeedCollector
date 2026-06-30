from pathlib import Path

import streamlit as st
import pandas as pd
import re
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
st.set_page_config(page_title="Threat Hunting Dashboard", layout="wide")
st.title("Hello world!!")

end_date = datetime.now().date()
start_date = end_date - timedelta(days=2)
date_range = st.date_input("", (start_date, end_date), key="hunt_date_range")

if isinstance(date_range, tuple) and len(date_range) == 2:
    start_date, end_date = date_range


misp = PyMISP(MISP_URL, MISP_KEY, False)
events = misp.search('events', date_to=end_date.strftime('%Y-%m-%d'), date_from=start_date.strftime('%Y-%m-%d'))
if not events:
    st.info("No Event found for the selected date range.")
else:
    sort_order = st.radio("↕️ Sort", ["New → Old", "Old → New"], horizontal=True)

    for event in events:
        try:
            if 'EventReport' in event['Event'] and len(event['Event']['EventReport']) > 1:
                title = ""
                match = re.search(r'\[([^\]]+)\]', event['Event']['info'])
                if match:
                    title = match.group(1)
                content = event['Event']['EventReport'][1]['content']
                label = f"{event['Event']['date']} | {title}"

                lines = content.splitlines(True)
                formatted = "".join(lines[3:]).replace("### 概要", f"### {title}")

                with st.expander(label, expanded=False):
                    st.markdown(formatted)
        except Exception as e:
            st.warning(f"Failed to read {event}: {e}")

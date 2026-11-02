from __future__ import annotations

from pathlib import Path

import streamlit as st

from phishing_analyzer import analyze_email, export_csv, export_pdf


st.set_page_config(page_title="PhishMail | Email Threat Analyzer", page_icon="🛡️", layout="wide")


def risk_color(score: int) -> str:
    if score <= 30:
        return "#15803d"
    if score <= 70:
        return "#b45309"
    return "#b91c1c"


st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp {
  background: radial-gradient(ellipse at 12% 0%, rgba(8,145,178,.18), transparent 34%),
              radial-gradient(ellipse at 95% 8%, rgba(99,102,241,.16), transparent 30%),
              #07111f;
  color: #e5edf7;
}
.block-container {padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1250px;}
header[data-testid="stHeader"] {background: rgba(7,17,31,.78);}
.hero {
  padding: 1.7rem 1.8rem; border: 1px solid rgba(103,232,249,.25);
  border-radius: 20px; margin-bottom: 1.2rem;
  background: linear-gradient(120deg, rgba(15,37,63,.97), rgba(8,83,105,.93) 65%, rgba(49,46,129,.9));
  box-shadow: 0 18px 45px rgba(0,0,0,.22);
}
.hero h1 {color: #f0f9ff; margin: 0 0 .4rem 0; font-size: 2.45rem; letter-spacing: -.04em;}
.hero p {color: #c7f4ff; margin: 0; font-size: 1.02rem;}
.brand-badge {display:inline-block; vertical-align:middle; font-size:.62rem; letter-spacing:.12em;
  color:#a5f3fc; border:1px solid rgba(165,243,252,.42); border-radius:999px; padding:.34rem .6rem; margin-left:.5rem;}
.stMarkdown, .stText, label, p, li {color: #d6e3f2;}
[data-testid="stWidgetLabel"] p {color:#dbeafe !important; font-weight:600;}
textarea, input, [data-baseweb="select"] > div {
  background-color:#0b1a2b !important; color:#e5edf7 !important;
  border-color:#29435c !important; border-radius:10px !important;
}
[data-testid="stFileUploader"] section {background:#0b1a2b; border:1px dashed #36536e; border-radius:14px;}
[data-testid="stMetric"] {background:linear-gradient(145deg,#0c1d30,#0b1727); border:1px solid #243e58; padding:16px; border-radius:14px;}
[data-testid="stMetricLabel"] {color:#9fb7ce !important;}
[data-testid="stMetricValue"] {color:#ecfeff !important;}
.stButton > button, .stDownloadButton > button {
  border-radius:10px; border:1px solid #247c94; font-weight:650;
  transition: transform .15s ease, border-color .15s ease;
}
.stButton > button[kind="primary"] {background:linear-gradient(90deg,#0891b2,#4f46e5); color:white; border:0;}
.stButton > button:hover, .stDownloadButton > button:hover {transform:translateY(-1px); border-color:#67e8f9;}
[data-testid="stAlert"] {border-radius:12px;}
hr {border-color:#20364d;}
[data-testid="stDataFrame"], [data-testid="stTable"] {border:1px solid #243e58; border-radius:12px; overflow:hidden;}
code {color:#a5f3fc !important;}
</style>
<div class="hero">
  <h1>PhishMail <span class="brand-badge">THREAT ANALYZER</span></h1>
  <p>Spot the phish. Protect your inbox. · Rule-based email risk analysis.</p>
</div>
""", unsafe_allow_html=True)
st.caption("Inspect email content, sender clues, and links for common phishing warning signs. Use the findings as guidance—not as a guarantee.")

sample_email = """From: Account Help <account-alert@example.com>
Subject: Action required: account access review

Hello,

We noticed an unusual sign-in attempt. To keep your account active,
review your recent activity within the next 24 hours.

Review your account here:
https://account-check.example.com/review

Do not reply with your password or verification code.

Account Support
"""

if "email_content" not in st.session_state:
    st.session_state.email_content = ""
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "report_files" not in st.session_state:
    st.session_state.report_files = {}


def load_sample_email() -> None:
    st.session_state.email_content = sample_email


left, right = st.columns([1, 1])
with left:
    st.text_area(
        "Email message to inspect",
        key="email_content",
        height=320,
        placeholder="Paste the email body, sender, subject, and any links here...",
    )
with right:
    uploaded_file = st.file_uploader("Import an email (.txt or .eml)", type=["txt", "eml"])
    st.info("Looks for urgent wording, unusual links, sender clues, and mismatched link text.")

st.button("Try the sample message", on_click=load_sample_email)

content = st.session_state.email_content
filename = ""
if uploaded_file is not None:
    content = uploaded_file.getvalue()
    filename = uploaded_file.name

analyze_clicked = st.button("Scan message", type="primary", use_container_width=True)

if analyze_clicked:
    if not content:
        st.warning("Paste an email message or import a .txt/.eml file to begin.")
        st.stop()

    st.session_state.analysis_result = analyze_email(content, filename)
    st.session_state.report_files = {}

result = st.session_state.analysis_result

if result:
    color = risk_color(result.risk_score)

    score_col, meta_col = st.columns([1, 2])
    with score_col:
        st.markdown(
            f"""
            <div style="border:1px solid #d4d4d8;border-radius:8px;padding:20px">
                <div style="font-size:14px;color:#52525b">Risk Score</div>
                <div style="font-size:44px;font-weight:700;color:{color}">{result.risk_score}/100</div>
                <div style="font-size:20px;font-weight:600;color:{color}">{result.risk_level}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with meta_col:
        st.subheader("Message overview")
        st.write(result.summary)
        st.write(f"**Sender:** {result.sender}")
        st.write(f"**Subject:** {result.subject}")
        st.write(f"**Analysis Date:** {result.analysis_date}")

    st.subheader("Warning signs found")
    if result.indicators:
        st.table(
            [
                {"Category": item.category, "Detail": item.detail, "Points": item.points}
                for item in result.indicators
            ]
        )
    else:
        st.success("No warning signs were detected by the current rules. This does not guarantee the email is safe.")

    st.subheader("Links in this message")
    link_col, count_col = st.columns([3, 1])
    with link_col:
        if result.urls:
            for url in result.urls:
                st.code(url, language=None)
        else:
            st.write("No URLs detected.")
    with count_col:
        st.metric("Links found", len(result.urls))

    st.subheader("Suggested next steps")
    for recommendation in result.recommendations:
        st.write(f"- {recommendation}")

    csv_data = export_csv(result).encode("utf-8")
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    timestamp = result.analysis_date.replace(":", "").replace("-", "").replace(" ", "_")
    csv_path = report_dir / f"phishmail_scan_{timestamp}.csv"
    pdf_path = report_dir / f"phishmail_scan_{timestamp}.pdf"

    if not csv_path.exists():
        csv_path.write_bytes(csv_data)

    download_col1, download_col2 = st.columns(2)
    with download_col1:
        st.download_button(
            "Export results as CSV",
            data=csv_data,
            file_name="phishmail_scan_report.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.caption(f"Saved to `{csv_path}`")
    with download_col2:
        try:
            pdf_data = export_pdf(result)
            if not pdf_path.exists():
                pdf_path.write_bytes(pdf_data)
            st.download_button(
                "Export results as PDF",
                data=pdf_data,
                file_name="phishmail_scan_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
            st.caption(f"Saved to `{pdf_path}`")
        except RuntimeError:
            st.warning("PDF export requires reportlab. Install dependencies with `pip install -r requirements.txt`.")

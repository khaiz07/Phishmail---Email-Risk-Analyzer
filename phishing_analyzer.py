from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.parser import BytesParser, Parser
from html import unescape
from typing import Iterable
from urllib.parse import urlparse


RISK_LEVELS = (
    (30, "Low Risk"),
    (70, "Medium Risk"),
    (100, "High Risk"),
)

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "s.id",
    "shorturl.at",
}

KNOWN_BRANDS = {
    "amazon": ["amazon.com"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "work",
    "support",
    "country",
    "tk",
    "ml",
    "ga",
    "cf",
}

KEYWORD_RULES = [
    ("Urgent action language", 10, [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bverify immediately\b",
        r"\bact now\b",
        r"\blast warning\b",
        r"\bwithin 24 hours\b",
        r"\byour account will be suspended\b",
        r"\bavoid account closure\b",
        r"\baccount closure\b",
    ]),
    ("Credential or password request", 18, [
        r"\bpassword\b",
        r"\blogin credentials\b",
        r"\bconfirm your identity\b",
        r"\bsign in to continue\b",
        r"\bre-enter\b.*\bpassword\b",
    ]),
    ("OTP or verification code request", 18, [
        r"\botp\b",
        r"\bone[- ]time password\b",
        r"\bverification code\b",
        r"\bsecurity code\b",
    ]),
    ("Banking or payment scam language", 15, [
        r"\bbank account\b",
        r"\bdebit card\b",
        r"\bcredit card\b",
        r"\bpayment failed\b",
        r"\btransaction\b",
        r"\brefund\b",
        r"\bwire transfer\b",
    ]),
    ("Prize or lottery scam language", 15, [
        r"\bwon (a )?prize\b",
        r"\blottery\b",
        r"\bjackpot\b",
        r"\bclaim your reward\b",
        r"\bcongratulations\b",
        r"\bgift card\b",
    ]),
    ("Fake account verification language", 16, [
        r"\bverify your account\b",
        r"\baccount verification\b",
        r"\bupdate your account\b",
        r"\bconfirm your account\b",
        r"\bsecurity alert\b",
    ]),
    ("Threatening consequence language", 12, [
        r"\bsuspended\b",
        r"\blocked\b",
        r"\bclosed\b",
        r"\bterminated\b",
        r"\bunauthorized access\b",
    ]),
]


URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)
HTML_LINK_PATTERN = re.compile(
    r"<a\s+[^>]*href=[\"'](?P<href>[^\"']+)[\"'][^>]*>(?P<label>.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
IP_HOST_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")


@dataclass
class Indicator:
    category: str
    detail: str
    points: int


@dataclass
class EmailData:
    subject: str = ""
    sender: str = ""
    body: str = ""
    raw: str = ""


@dataclass
class AnalysisResult:
    analysis_date: str
    subject: str
    sender: str
    summary: str
    urls: list[str]
    indicators: list[Indicator] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low Risk"
    recommendations: list[str] = field(default_factory=list)


def parse_email_content(content: str | bytes, filename: str = "") -> EmailData:
    """Parse plain text or .eml content into fields used by the analyzer."""
    raw_text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content

    if filename.lower().endswith(".eml") or _looks_like_eml(raw_text):
        try:
            message = (
                BytesParser(policy=policy.default).parsebytes(content)
                if isinstance(content, bytes)
                else Parser(policy=policy.default).parsestr(raw_text)
            )
            body = _extract_message_body(message)
            return EmailData(
                subject=str(message.get("subject", "")),
                sender=str(message.get("from", "")),
                body=body,
                raw=raw_text,
            )
        except Exception:
            pass

    sender = ""
    subject = ""
    for line in raw_text.splitlines()[:30]:
        lower = line.lower()
        if lower.startswith("from:"):
            sender = line.split(":", 1)[1].strip()
        elif lower.startswith("subject:"):
            subject = line.split(":", 1)[1].strip()

    return EmailData(subject=subject, sender=sender, body=raw_text, raw=raw_text)


def analyze_email(content: str | bytes, filename: str = "") -> AnalysisResult:
    email_data = parse_email_content(content, filename)
    analysis_text = " ".join([email_data.subject, email_data.sender, email_data.body])
    indicators: list[Indicator] = []

    indicators.extend(_analyze_keywords(analysis_text))
    urls = extract_urls(email_data.body)
    indicators.extend(_analyze_urls(email_data.body, urls))
    indicators.extend(_analyze_sender(email_data.sender, analysis_text))

    score = min(100, sum(indicator.points for indicator in indicators))
    level = _risk_level(score)
    return AnalysisResult(
        analysis_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        subject=email_data.subject or "(No subject detected)",
        sender=email_data.sender or "(No sender detected)",
        summary=_summarize_body(email_data.body),
        urls=urls,
        indicators=indicators,
        risk_score=score,
        risk_level=level,
        recommendations=_recommendations(level, indicators),
    )


def extract_urls(text: str) -> list[str]:
    found = []
    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(").,;!]")
        if url.lower().startswith("www."):
            url = "http://" + url
        found.append(url)
    return list(dict.fromkeys(found))


def export_csv(result: AnalysisResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Analysis Date", result.analysis_date])
    writer.writerow(["Sender", result.sender])
    writer.writerow(["Subject", result.subject])
    writer.writerow(["Risk Score", result.risk_score])
    writer.writerow(["Risk Level", result.risk_level])
    writer.writerow([])
    writer.writerow(["Category", "Detail", "Points"])
    for indicator in result.indicators:
        writer.writerow([indicator.category, indicator.detail, indicator.points])
    writer.writerow([])
    writer.writerow(["URLs"])
    for url in result.urls:
        writer.writerow([url])
    writer.writerow([])
    writer.writerow(["Recommendations"])
    for recommendation in result.recommendations:
        writer.writerow([recommendation])
    return output.getvalue()


def export_pdf(result: AnalysisResult) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("Install reportlab to export PDF reports.") from exc

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title="PhishMail Scan Report",
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.65 * inch,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#111827"),
            spaceAfter=14,
            alignment=1,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#1f2937"),
            spaceBefore=8,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportBody",
            parent=styles["BodyText"],
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#374151"),
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallMuted",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#6b7280"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableHeader",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10,
            textColor=colors.white,
            alignment=1,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableCell",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#111827"),
            wordWrap="CJK",
        )
    )

    risk_color = {
        "Low Risk": colors.HexColor("#15803d"),
        "Medium Risk": colors.HexColor("#b45309"),
        "High Risk": colors.HexColor("#b91c1c"),
    }.get(result.risk_level, colors.HexColor("#374151"))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(document.leftMargin, 0.35 * inch, "PhishMail Email Risk Scanner")
        canvas.drawRightString(
            letter[0] - document.rightMargin,
            0.35 * inch,
            f"Page {document.page}",
        )
        canvas.restoreState()

    meta_rows = [
        ["Analysis Date", result.analysis_date],
        ["Sender", result.sender],
        ["Subject", result.subject],
        ["Risk Score", f"{result.risk_score}/100"],
        ["Risk Level", result.risk_level],
    ]
    meta_table = Table(
        [
            [
                Paragraph(f"<b>{_escape_pdf(label)}</b>", styles["ReportBody"]),
                Paragraph(_escape_pdf(value), styles["ReportBody"]),
            ]
            for label, value in meta_rows
        ],
        colWidths=[1.35 * inch, 5.0 * inch],
        hAlign="LEFT",
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TEXTCOLOR", (1, 4), (1, 4), risk_color),
            ]
        )
    )

    story = [
        Paragraph("PhishMail Scan Report", styles["ReportTitle"]),
        meta_table,
        Spacer(1, 10),
        Paragraph("Message Overview", styles["SectionHeading"]),
        Paragraph(_escape_pdf(result.summary), styles["ReportBody"]),
        Spacer(1, 8),
        Paragraph("Warning Signs Found", styles["SectionHeading"]),
    ]

    indicator_rows = [
        [
            Paragraph("Category", styles["TableHeader"]),
            Paragraph("Detail", styles["TableHeader"]),
            Paragraph("Points", styles["TableHeader"]),
        ]
    ]
    indicator_rows.extend(
        [
            [
                Paragraph(_escape_pdf(i.category), styles["TableCell"]),
                Paragraph(_escape_pdf(i.detail), styles["TableCell"]),
                Paragraph(str(i.points), styles["TableCell"]),
            ]
            for i in result.indicators
        ]
        or [
            [
                Paragraph("None", styles["TableCell"]),
                Paragraph("No indicators detected", styles["TableCell"]),
                Paragraph("0", styles["TableCell"]),
            ]
        ]
    )
    indicator_table = Table(
        indicator_rows,
        colWidths=[1.65 * inch, 4.15 * inch, 0.55 * inch],
        repeatRows=1,
        hAlign="LEFT",
    )
    indicator_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (2, 1), (2, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ]
        )
    )
    story.append(indicator_table)
    story.extend([Spacer(1, 10), Paragraph("Links in Message", styles["SectionHeading"])])
    for url in result.urls or ["No URLs detected"]:
        story.append(Paragraph(_escape_pdf(url), styles["ReportBody"]))
    story.extend([Spacer(1, 8), Paragraph("Suggested Next Steps", styles["SectionHeading"])])
    for recommendation in result.recommendations:
        story.append(Paragraph(f"- {_escape_pdf(recommendation)}", styles["ReportBody"]))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "This report is rule-based and should be used with sender verification and normal security review.",
            styles["SmallMuted"],
        )
    )

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def _analyze_keywords(text: str) -> Iterable[Indicator]:
    lowered = text.lower()
    for category, points, patterns in KEYWORD_RULES:
        matches = sorted(
            {match.group(0) for pattern in patterns if (match := re.search(pattern, lowered))}
        )
        if matches:
            detail = f"Matched phrase(s): {', '.join(matches[:4])}"
            if len(matches) > 4:
                detail += f" and {len(matches) - 4} more"
            yield Indicator(category, detail, points)


def _analyze_urls(body: str, urls: list[str]) -> Iterable[Indicator]:
    if len(urls) >= 3:
        yield Indicator("Multiple links", f"{len(urls)} links detected in the email.", 8)

    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().removeprefix("www.")
        if not host:
            continue
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if IP_HOST_PATTERN.match(host):
            yield Indicator("IP address URL", f"URL uses an IP address instead of a domain: {url}", 18)
        if host in SHORTENER_DOMAINS:
            yield Indicator("Shortened URL", f"Shortened link detected: {url}", 16)
        if "@" in urlparse(url).netloc:
            yield Indicator("Deceptive URL format", f"URL contains '@', which can hide the real destination: {url}", 18)
        if tld in SUSPICIOUS_TLDS:
            yield Indicator("Suspicious URL domain", f"Domain uses a commonly abused TLD '.{tld}': {url}", 10)
        if _has_brand_impersonation(host):
            yield Indicator("Possible brand impersonation URL", f"URL domain may be impersonating a known brand: {host}", 14)

    for label, actual in _extract_html_link_pairs(body):
        displayed_urls = extract_urls(unescape(re.sub(r"<[^>]+>", " ", label)))
        for displayed in displayed_urls:
            displayed_host = (urlparse(displayed).hostname or "").removeprefix("www.").lower()
            actual_host = (urlparse(actual).hostname or "").removeprefix("www.").lower()
            if displayed_host and actual_host and displayed_host != actual_host:
                yield Indicator(
                    "Displayed/actual link mismatch",
                    f"Displayed domain '{displayed_host}' points to '{actual_host}'.",
                    22,
                )


def _analyze_sender(sender: str, text: str) -> Iterable[Indicator]:
    if not sender:
        return

    addresses = EMAIL_PATTERN.findall(sender)
    if not addresses:
        yield Indicator("Missing sender email", "Sender field does not contain a clear email address.", 8)
        return

    address = addresses[0].lower()
    domain = address.split("@", 1)[1].removeprefix("www.")

    if domain in FREE_EMAIL_DOMAINS and _mentions_organization(text):
        yield Indicator(
            "Free email sender",
            f"Sender uses a free email domain while claiming organizational context: {domain}",
            14,
        )
    if _has_brand_impersonation(domain):
        yield Indicator("Misspelled or suspicious sender domain", f"Sender domain may impersonate a brand: {domain}", 18)
    if any(word in domain for word in ["security", "verify", "support", "account", "login"]) and not _is_known_brand_domain(domain):
        yield Indicator("Suspicious sender domain wording", f"Sender domain uses trust-related wording: {domain}", 10)


def _extract_html_link_pairs(body: str) -> list[tuple[str, str]]:
    pairs = []
    for match in HTML_LINK_PATTERN.finditer(body):
        href = match.group("href")
        if href.lower().startswith("www."):
            href = "http://" + href
        if href.lower().startswith(("http://", "https://")):
            pairs.append((match.group("label"), href))
    return pairs


def _looks_like_eml(text: str) -> bool:
    first_lines = "\n".join(text.splitlines()[:20]).lower()
    return any(header in first_lines for header in ["from:", "to:", "subject:", "received:", "mime-version:"])


def _extract_message_body(message) -> str:
    if message.is_multipart():
        parts = []
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            if content_type in {"text/plain", "text/html"}:
                try:
                    parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="replace"))
        return "\n".join(parts)
    try:
        return message.get_content()
    except Exception:
        payload = message.get_payload(decode=True)
        return payload.decode("utf-8", errors="replace") if payload else str(message.get_payload())


def _summarize_body(body: str) -> str:
    cleaned = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
    if not cleaned:
        return "No email body detected."
    return cleaned[:450] + ("..." if len(cleaned) > 450 else "")


def _risk_level(score: int) -> str:
    for max_score, label in RISK_LEVELS:
        if score <= max_score:
            return label
    return "High Risk"


def _recommendations(level: str, indicators: list[Indicator]) -> list[str]:
    recommendations = [
        "Do not click links or download attachments until the sender is verified.",
        "Confirm the request through an official website, app, or known phone number.",
    ]
    categories = {indicator.category for indicator in indicators}
    if any("URL" in category or "link" in category.lower() for category in categories):
        recommendations.append("Hover over links and compare the displayed domain with the actual destination.")
    if any("sender" in category.lower() or "domain" in category.lower() for category in categories):
        recommendations.append("Check the sender domain carefully for misspellings or impersonation.")
    if level == "High Risk":
        recommendations.append("Report this email to your security team and delete it from the inbox.")
    return recommendations


def _has_brand_impersonation(domain: str) -> bool:
    compact = domain.replace("-", "").replace(".", "").replace("0", "o").replace("1", "l")
    for brand, valid_domains in KNOWN_BRANDS.items():
        if brand in compact and not any(domain.endswith(valid) for valid in valid_domains):
            return True
    return False


def _is_known_brand_domain(domain: str) -> bool:
    return any(domain.endswith(valid) for domains in KNOWN_BRANDS.values() for valid in domains)


def _mentions_organization(text: str) -> bool:
    lowered = text.lower()
    organization_words = ["bank", "paypal", "amazon", "microsoft", "apple", "google", "netflix", "account", "support"]
    return any(word in lowered for word in organization_words)


def _escape_pdf(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

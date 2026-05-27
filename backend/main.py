import re
import json
import uuid

from datetime import datetime

from email import policy
from email.parser import BytesParser

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "suspended",
    "password",
    "bank",
    "login",
    "click",
    "credentials",
    "limited time",
    "security alert"
]


SUSPICIOUS_DOMAINS = [
    ".ru",
    ".xyz",
    ".tk",
    ".top",
    ".gq"
]


DATABASE_FILE = "storage/cases.json"


def analyze_psychology(content):

    content = content.lower()

    detected_tactics = []

    if any(word in content for word in [
        "urgent",
        "immediately",
        "within 24 hours",
        "suspended"
    ]):
        detected_tactics.append(
            "Urgency Manipulation"
        )

    if any(word in content for word in [
        "verify",
        "password",
        "credentials",
        "login"
    ]):
        detected_tactics.append(
            "Credential Harvesting"
        )

    if any(word in content for word in [
        "bank",
        "security team",
        "microsoft",
        "paypal"
    ]):
        detected_tactics.append(
            "Authority Impersonation"
        )

    if any(word in content for word in [
        "account locked",
        "failure to act",
        "permanently suspended"
    ]):
        detected_tactics.append(
            "Fear-Based Pressure"
        )

    if len(detected_tactics) == 0:

        detected_tactics.append(
            "No major manipulation patterns detected"
        )

    return detected_tactics


def analyze_url_reputation(urls):

    url_analysis = []

    reputation_score = 0

    for url in urls:

        reputation = "SAFE"

        reasons = []

        for domain in SUSPICIOUS_DOMAINS:

            if domain in url:

                reputation = "SUSPICIOUS"

                reasons.append(
                    f"Suspicious domain detected: {domain}"
                )

                reputation_score += 20

        if "login" in url.lower():

            reputation = "SUSPICIOUS"

            reasons.append(
                "Login-themed URL detected"
            )

            reputation_score += 15

        if "verify" in url.lower():

            reputation = "SUSPICIOUS"

            reasons.append(
                "Verification-themed URL detected"
            )

            reputation_score += 15

        if "secure" in url.lower():

            reasons.append(
                "Potential impersonation keyword detected"
            )

            reputation_score += 10

        url_analysis.append({
            "url": url,
            "reputation": reputation,
            "reasons": reasons
        })

    return url_analysis, reputation_score


def analyze_headers(parsed_email):

    header_findings = []

    header_score = 0

    sender = parsed_email.get("From", "")

    reply_to = parsed_email.get("Reply-To", "")

    received_spf = parsed_email.get("Received-SPF", "")

    return_path = parsed_email.get("Return-Path", "")

    if reply_to and reply_to != sender:

        header_findings.append(
            "Reply-To mismatch detected"
        )

        header_score += 25

    if "fail" in received_spf.lower():

        header_findings.append(
            "SPF authentication failure detected"
        )

        header_score += 30

    suspicious_sender_patterns = [
        ".ru",
        ".tk",
        ".xyz",
        "support-security",
        "verify-account"
    ]

    for pattern in suspicious_sender_patterns:

        if pattern in sender.lower():

            header_findings.append(
                f"Suspicious sender pattern detected: {pattern}"
            )

            header_score += 20

    if return_path and sender:

        if return_path.lower() not in sender.lower():

            header_findings.append(
                "Return-Path mismatch detected"
            )

            header_score += 20

    if len(header_findings) == 0:

        header_findings.append(
            "No major header anomalies detected"
        )

    return header_findings, header_score


def generate_final_verdict(score):

    if score >= 85:

        return {
            "classification": "CONFIRMED PHISHING",
            "confidence": "VERY HIGH",
            "recommended_action": (
                "Block sender, quarantine email, "
                "investigate affected users immediately."
            )
        }

    elif score >= 60:

        return {
            "classification": "LIKELY PHISHING",
            "confidence": "HIGH",
            "recommended_action": (
                "Escalate to SOC analyst for manual review."
            )
        }

    elif score >= 40:

        return {
            "classification": "SUSPICIOUS",
            "confidence": "MEDIUM",
            "recommended_action": (
                "Monitor sender and validate legitimacy."
            )
        }

    else:

        return {
            "classification": "LOW RISK",
            "confidence": "LOW",
            "recommended_action": (
                "No immediate action required."
            )
        }


def extract_iocs(body, sender):

    urls = re.findall(
        r'https?://[^\s]+',
        body
    )

    domains = []

    for url in urls:

        domain_match = re.findall(
            r'https?://([^/]+)',
            url
        )

        if domain_match:
            domains.append(domain_match[0])

    email_addresses = re.findall(
        r'[\w\.-]+@[\w\.-]+',
        body
    )

    sender_email = re.findall(
        r'[\w\.-]+@[\w\.-]+',
        sender
    )

    if sender_email:
        email_addresses.extend(sender_email)

    return {
        "urls": list(set(urls)),
        "domains": list(set(domains)),
        "email_addresses": list(set(email_addresses))
    }


@app.get("/")
def home():

    return {
        "status": "PhishLens Backend Running"
    }


@app.get("/cases")
def get_cases():

    with open(DATABASE_FILE, "r") as file:
        data = json.load(file)

    return data


@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):

    raw_content = await file.read()

    parsed_email = BytesParser(
        policy=policy.default
    ).parsebytes(raw_content)

    sender = parsed_email.get("From", "Unknown")

    receiver = parsed_email.get("To", "Unknown")

    subject = parsed_email.get("Subject", "No Subject")

    body = ""

    if parsed_email.is_multipart():

        for part in parsed_email.walk():

            if part.get_content_type() == "text/plain":

                try:
                    body += part.get_content()
                except:
                    pass

    else:

        try:
            body = parsed_email.get_content()
        except:
            body = ""

    body_lower = body.lower()

    psychology_analysis = analyze_psychology(body)

    detected_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in body_lower:
            detected_keywords.append(keyword)

    urls = re.findall(
        r'https?://[^\s]+',
        body
    )

    url_reputation_analysis, reputation_score = analyze_url_reputation(urls)

    header_analysis, header_score = analyze_headers(parsed_email)

    iocs = extract_iocs(body, sender)

    phishing_score = 0

    phishing_score += len(detected_keywords) * 10

    phishing_score += len(urls) * 15

    phishing_score += reputation_score

    phishing_score += header_score

    if phishing_score > 100:
        phishing_score = 100

    if phishing_score >= 70:
        risk_level = "HIGH RISK"

    elif phishing_score >= 40:
        risk_level = "MEDIUM RISK"

    else:
        risk_level = "LOW RISK"

    verdict_data = generate_final_verdict(
        phishing_score
    )

    analyst_report = f"""
========== PHISHLENS INVESTIGATION REPORT ==========

CASE INFORMATION

Filename:
{file.filename}

Timestamp:
{datetime.now()}

--------------------------------------------

EMAIL METADATA

From:
{sender}

To:
{receiver}

Subject:
{subject}

--------------------------------------------

RISK ANALYSIS

Risk Level:
{risk_level}

Phishing Score:
{phishing_score}/100

Threat Classification:
{verdict_data['classification']}

Confidence Level:
{verdict_data['confidence']}

--------------------------------------------

HEADER ANALYSIS

{chr(10).join(header_analysis)}

--------------------------------------------

DETECTED PHISHING KEYWORDS

{chr(10).join(detected_keywords)}

--------------------------------------------

EXTRACTED URLS

{chr(10).join(urls)}

--------------------------------------------

EXTRACTED IOCS

URLs:
{iocs['urls']}

Domains:
{iocs['domains']}

Email Addresses:
{iocs['email_addresses']}

--------------------------------------------

AI URL REPUTATION ANALYSIS

{url_reputation_analysis}

--------------------------------------------

AI PSYCHOLOGICAL ANALYSIS

{chr(10).join(psychology_analysis)}

--------------------------------------------

RECOMMENDED ACTIONS

{verdict_data['recommended_action']}

--------------------------------------------

FINAL ANALYST VERDICT

This email demonstrates phishing-related
behavioral, technical, and psychological
characteristics consistent with malicious
credential-harvesting campaigns.
"""

    case_data = {
        "case_id": str(uuid.uuid4()),
        "timestamp": str(datetime.now()),
        "filename": file.filename,
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "risk_level": risk_level,
        "phishing_score": phishing_score,
        "classification": verdict_data["classification"],
        "confidence": verdict_data["confidence"],
        "recommended_action":
            verdict_data["recommended_action"],
        "header_analysis": header_analysis,
        "keywords_detected": detected_keywords,
        "urls_detected": urls,
        "url_reputation_analysis":
            url_reputation_analysis,
        "psychology_analysis":
            psychology_analysis,
        "iocs": iocs,
        "report": analyst_report
    }

    with open(DATABASE_FILE, "r") as db_file:
        existing_cases = json.load(db_file)

    existing_cases.append(case_data)

    with open(DATABASE_FILE, "w") as db_file:
        json.dump(existing_cases, db_file, indent=4)

    return case_data
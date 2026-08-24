#!/usr/bin/env python3
"""
FreshCart Phishing Risk Scorer
--------------------------------
A lightweight, reusable tool that scores email artifacts for phishing risk
using the same weighted indicator model documented in the Email & Phishing
Security analysis (07_Email_Phishing/Analysis).

Usage:
    python3 phishing_scorer.py

The script scores each email defined in EMAILS below and prints a
classification (Suspicious / Legitimate) with a breakdown of which
indicators triggered.
"""

INTERNAL_DOMAIN = "freshcart.local"

WEIGHTS = {
    "domain_mismatch": 30,
    "reply_to_mismatch": 15,
    "urgency_language": 20,
    "suspicious_link_or_attachment": 25,
    "generic_tone": 10,
}

URGENCY_KEYWORDS = ["urgent", "24 hours", "immediately", "suspension", "action required", "expire"]
SUSPICIOUS_DOMAIN_HINTS = ["-secure", "-verify", "-invoices", "-portal"]


def extract_domain(address):
    # Handle "Display Name <user@domain.com>" format
    if "<" in address and ">" in address:
        address = address.split("<", 1)[1].split(">", 1)[0]
    return address.split("@")[-1].strip().lower()


def score_email(email):
    reasons = []
    score = 0

    from_domain = extract_domain(email["from"])
    reply_domain = extract_domain(email.get("reply_to", email["from"]))

    # Domain mismatch: sender domain isn't the trusted internal domain
    if from_domain != INTERNAL_DOMAIN:
        score += WEIGHTS["domain_mismatch"]
        reasons.append(f"Sender domain '{from_domain}' is not the trusted internal domain")

    # Reply-To mismatch
    if reply_domain != from_domain:
        score += WEIGHTS["reply_to_mismatch"]
        reasons.append(f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'")

    # Urgency language
    body_lower = email["body"].lower()
    if any(word in body_lower for word in URGENCY_KEYWORDS):
        score += WEIGHTS["urgency_language"]
        reasons.append("Urgency/pressure language detected in body")

    # Suspicious link or attachment
    has_suspicious_link = any(hint in email.get("link", "") for hint in SUSPICIOUS_DOMAIN_HINTS)
    has_macro_attachment = email.get("attachment", "").endswith((".xlsm", ".docm", ".zip"))
    if has_suspicious_link or has_macro_attachment:
        score += WEIGHTS["suspicious_link_or_attachment"]
        reasons.append("Suspicious external link or macro-enabled attachment present")

    # Generic tone (very rough heuristic: greeting doesn't use a real name)
    if "dear employee" in body_lower or "dear finance team" in body_lower:
        score += WEIGHTS["generic_tone"]
        reasons.append("Generic greeting instead of personalized salutation")

    classification = "Suspicious (Phishing)" if score >= 50 else "Legitimate"
    return score, classification, reasons


EMAILS = [
    {
        "id": "Email 1",
        "from": "IT Support <it-support@freshcart-secure.com>",
        "reply_to": "helpdesk@freshcart-secure.com",
        "subject": "URGENT: Your password expires in 24 hours",
        "body": "Dear Employee, your password will expire within 24 hours. Verify immediately.",
        "link": "http://freshcart-portal-verify.com/reset",
    },
    {
        "id": "Email 2",
        "from": "IT Support <it-support@freshcart.local>",
        "reply_to": "it-support@freshcart.local",
        "subject": "Scheduled maintenance - Friday 10 PM",
        "body": "Hi team, we will be performing scheduled maintenance this Friday.",
        "link": "",
    },
    {
        "id": "Email 3",
        "from": "HR Team <hr@freshcart.local>",
        "reply_to": "hr@freshcart.local",
        "subject": "Reminder: submit your timesheet by Monday",
        "body": "Hello everyone, please remember to submit your timesheet.",
        "link": "",
    },
    {
        "id": "Email 4",
        "from": "Billing Dept <billing@freshcart-invoices.net>",
        "reply_to": "payments-support@freshcart-invoices.net",
        "subject": "Outstanding invoice #4471 - action required",
        "body": "Dear Finance Team, please open the attached file and process payment.",
        "link": "",
        "attachment": "Invoice_4471.xlsm",
    },
]


def main():
    print(f"{'Email':<10}{'Score':<8}{'Classification':<25}Reasons")
    print("-" * 90)
    for email in EMAILS:
        score, classification, reasons = score_email(email)
        print(f"{email['id']:<10}{score:<8}{classification:<25}" + "; ".join(reasons))


if __name__ == "__main__":
    main()
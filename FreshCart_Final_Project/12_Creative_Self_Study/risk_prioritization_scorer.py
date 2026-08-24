#!/usr/bin/env python3
"""
FreshCart Risk Prioritization Scorer
-------------------------------------
A lightweight, reusable tool that turns the qualitative reasoning used in the
Central Risk Register (08_Vulnerability_Management/Risk_Register/Organization.docx)
into a transparent, weighted numeric score, so risk ranking does not rely on
one reviewer's subjective ordering alone.

Each finding is rated 1-5 on four factors (Technical Severity, Exposure,
Access Ease, Business Impact). The weighted formula below produces a 0-100
score used to rank findings.

Usage:
    python3 risk_prioritization_scorer.py
"""

WEIGHTS = {
    "severity": 0.35,       # how serious the weakness is on its own
    "exposure": 0.25,       # how reachable it is (internet/DMZ vs internal-only)
    "access_ease": 0.20,    # how little an attacker needs to exploit it (5 = no credentials needed)
    "business_impact": 0.20,  # consequence to FreshCart if exploited
}

# Ratings are 1-5, taken directly from the reasoning already documented in the
# Vulnerability Register (08_Vulnerability_Management) and Organization.docx.
FINDINGS = {
    "WEB-03 - SQL Injection Auth Bypass": {
        "severity": 5, "exposure": 5, "access_ease": 5, "business_impact": 5,
        "status": "Open",
    },
    "VULN-01 - Firewall Admin Interface over HTTP": {
        "severity": 3, "exposure": 2, "access_ease": 2, "business_impact": 4,
        "status": "Open",
    },
    "NET-01 - DMZ Not Isolated from Internal LAN": {
        "severity": 4, "exposure": 4, "access_ease": 3, "business_impact": 4,
        "status": "Resolved",
    },
    "DATA-01 - Customer Data Readable by Any Account": {
        "severity": 4, "exposure": 2, "access_ease": 2, "business_impact": 4,
        "status": "Resolved",
    },
    "EV-01 - Phishing Email Targeting finance01": {
        "severity": 3, "exposure": 3, "access_ease": 2, "business_impact": 4,
        "status": "Monitoring / user-awareness control",
    },
}


def score(finding):
    raw = sum(WEIGHTS[k] * finding[k] for k in WEIGHTS)
    return round(raw * 20, 1)  # scale 1-5 weighted average to 0-100


def rank_findings(findings=FINDINGS):
    scored = [(name, score(f), f["status"]) for name, f in findings.items()]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored


def main():
    ranked = rank_findings()
    print(f"{'Rank':<5}{'Score':<8}{'Status':<35}{'Finding'}")
    print("-" * 90)
    for i, (name, s, status) in enumerate(ranked, start=1):
        print(f"{i:<5}{s:<8}{status:<35}{name}")


if __name__ == "__main__":
    main()

# 🛡️ PhishGuard AI — Intelligent Phishing & Threat Intelligence Platform

<p align="center">
  <img src="static/logo.png" alt="PhishGuard AI Logo" width="120" style="border-radius: 20px; box-shadow: 0 8px 24px rgba(0,0,0,0.12);" />
</p>

<p align="center">
  <strong>Enterprise-Grade Phishing Website & Threat Detection System Powered by Machine Learning & Explainable AI (XAI)</strong>
</p>

<p align="center">
  <a href="https://github.com/harshil51/PishGuard-AI"><img src="https://img.shields.io/badge/Repository-PhishGuard--AI-blue?style=for-the-badge&logo=github" alt="GitHub Repo"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"></a>
  <a href="https://flask.palletsprojects.com/"><img src="https://img.shields.io/badge/Flask-2.0.2-black?style=for-the-badge&logo=flask&logoColor=white" alt="Flask Backend"></a>
  <a href="https://scikit-learn.org/"><img src="https://img.shields.io/badge/Model-Gradient%20Boosting-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="Scikit-Learn"></a>
  <a href="#-ai-performance--model-benchmarking"><img src="https://img.shields.io/badge/Accuracy-97.42%25-success?style=for-the-badge" alt="Accuracy"></a>
  <a href="#-ai-performance--model-benchmarking"><img src="https://img.shields.io/badge/F1--Score-97.72%25-brightgreen?style=for-the-badge" alt="F1 Score"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License: MIT"></a>
</p>

---

## 📑 Table of Contents

- [Executive Overview](#-executive-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [AI Performance & Model Benchmarking](#-ai-performance--model-benchmarking)
- [Feature Engineering Pipeline (30 Features)](#-feature-engineering-pipeline-30-features)
- [Heuristic Email Threat Analyzer](#-heuristic-email-threat-analyzer)
- [Defensive Engineering & Security Safeguards](#-defensive-engineering--security-safeguards)
- [Interactive Web Command Center](#-interactive-web-command-center)
- [RESTful API Reference](#-restful-api-reference)
- [Project Directory Structure](#-project-directory-structure)
- [Quickstart & Installation Guide](#-quickstart--installation-guide)
- [Model Training & Serialization](#-model-training--serialization)
- [Production Deployment](#-production-deployment)
- [Author & Acknowledgments](#-author--acknowledgments)
- [License](#-license)

---

## 🌐 Executive Overview

Phishing remains the primary attack vector behind over **90% of corporate data breaches worldwide**, causing billions of dollars in annual losses. Traditional defense mechanisms—such as static URL blacklists and simple DNS filters—suffer from inherent latency: by the time a newly registered phishing domain is reported and blacklisted, the damage is already done.

**PhishGuard AI** solves this problem by combining **advanced machine learning classification** with **dynamic heuristic exfiltration analysis** and **Explainable AI (XAI)**. Instead of relying solely on retroactive blocklists, PhishGuard AI evaluates real-time lexical anomalies, content-level Document Object Model (DOM) hooks, SSL/TLS characteristics, and WHOIS domain metadata to detect zero-day phishing sites within milliseconds.

### Core Value Propositions
- 🎯 **97.42% Test Accuracy** and **98.87% Recall** on unseen adversarial URLs.
- 🔍 **Explainable AI (XAI)**: Every prediction comes with transparent threat indicator tags categorized by severity (`Danger`, `Warning`, `Safe`).
- 🛡️ **Built-in SOC Safeguards**: Automated URL defanging (`hxxps[://]`) and Server-Side Request Forgery (SSRF) validation prevent analysts from accidental triggers or internal network scanning.
- ✉️ **Integrated Email Threat Scanner**: Heuristic detection of sender spoofing, psychological urgency coercion, and credential harvesting patterns.
- 📊 **Embedded SQLite Audit Trail & Model Telemetry**: Persistent logging of every scan query, live confusion matrix visualizer, and feature importance rankings.

---

## ✨ Key Features

| Capability | Technical Implementation | Security Benefit |
| :--- | :--- | :--- |
| **URL Threat Scanner** | 30-feature extraction pipeline feeding an optimized Gradient Boosting Classifier | Identifies zero-hour phishing URLs before they appear on commercial blacklists |
| **Explainable AI (XAI)** | Granular indicator breakdown with color-coded severity tags | Provides actionable diagnostic reasoning for SOC analysts rather than a black-box score |
| **Email Threat Analyzer** | Regex pattern matching for social engineering, brand spoofing, and credential hooks | Detects phishing attempts at the inbox boundary before users interact with payload URLs |
| **URL Defanging** | Automatic conversion of active links (`https://` → `hxxps[://]`, `.` → `[.]`) | Prevents accidental clicks and automated link preview triggers in security operations |
| **SSRF Mitigation** | RFC 1918, loopback (`127.0.0.1`), and link-local address pre-flight checks | Blocks attackers from leveraging the scanner to probe internal infrastructure |
| **Audit Trail & Forensics** | SQLite database (`phishguard.db`) with instant search, verdict filtering, and CSV export | Enables security teams to review past incidents and verify compliance records |
| **Interactive Telemetry** | Dynamic confusion matrix, precision/recall tracking, and feature importance chart | Transparent view into model reliability and continuous operational metrics |
| **Modern Multi-Theme UI** | Theme engine featuring Warm Cream, Pure White, and Cyber Dark with Anti-FOUC persistence | Ergonomic dashboard optimized for high-intensity SOC environments |

---

## 🏛️ System Architecture

```
                                  ┌───────────────────────────────┐
                                  │      Client Web Browser       │
                                  │  (Interactive SPA Dashboard)  │
                                  └───────────────┬───────────────┘
                                                  │
                                    HTTP POST / JSON Requests
                                                  │
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │    Flask Application Engine   │
                                  │          (`app.py`)           │
                                  └───────┬───────────────┬───────┘
                                          │               │
                    ┌─────────────────────┘               └─────────────────────┐
                    ▼                                                           ▼
    ┌──────────────────────────────┐                            ┌──────────────────────────────┐
    │     URL Scanning Engine      │                            │     Email Threat Scanner     │
    │     (`core/feature.py`)      │                            │  (`core/email_scanner.py`)   │
    └───────────────┬──────────────┘                            └───────────────┬──────────────┘
                    │                                                           │
        ┌───────────┴───────────┐                                               │
        ▼                       ▼                                               │
┌──────────────┐        ┌──────────────┐                                        │
│ SSRF Guard   │        │ URL Defang   │                                        │
│  Validation  │        │  Formatter   │                                        │
└───────┬──────┘        └───────┬──────┘                                        │
        │                       │                                               │
        └───────────┬───────────┘                                               │
                    │                                                           │
                    ▼                                                           ▼
    ┌──────────────────────────────┐                            ┌──────────────────────────────┐
    │  30-Feature Extraction Vector│                            │ Heuristic NLP & Brand Engine │
    │ (Lexical, DOM, WHOIS, Net)   │                            │ (Urgency, Spoofing, Harvest) │
    └───────────────┬──────────────┘                            └───────────────┬──────────────┘
                    │                                                           │
                    ▼                                                           │
    ┌──────────────────────────────┐                                            │
    │  Gradient Boosting Model     │                                            │
    │     (`models/model.pkl`)     │                                            │
    └───────────────┬──────────────┘                                            │
                    │                                                           │
                    └─────────────────────┬─────────────────────────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │      Database & Persistence     │
                         │ SQLite Engine (`core/database`) │
                         │     (`data/phishguard.db`)      │
                         └────────────────┬────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │   Explainable AI Threat Verdict │
                         │ (SAFE / SUSPICIOUS / PHISHING)  │
                         └─────────────────────────────────┘
```

---

## 🧠 AI Performance & Model Benchmarking

To ensure state-of-the-art predictive performance, **10 different classification algorithms** were trained and evaluated on an extensive dataset of **11,055 verified legitimate and phishing URLs**.

### Model Comparison Benchmark

| Rank | Model Name | Accuracy | F1 Score | Recall | Precision | Status |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| 🥇 | **Gradient Boosting Classifier** | **97.42%** | **0.9772** | **0.9887** | **0.9660** | **✅ Deployed in Production** |
| 🥈 | CatBoost Classifier | 97.20% | 0.9750 | 0.9940 | 0.9890 | Evaluated |
| 🥉 | XGBoost Classifier | 96.90% | 0.9730 | 0.9930 | 0.9840 | Evaluated |
| 4 | Multi-Layer Perceptron (MLP) | 96.90% | 0.9730 | 0.9950 | 0.9810 | Evaluated |
| 5 | Random Forest Classifier | 96.70% | 0.9710 | 0.9930 | 0.9900 | Evaluated |
| 6 | Support Vector Machine (SVM) | 96.40% | 0.9680 | 0.9800 | 0.9650 | Evaluated |
| 7 | Decision Tree Classifier | 96.00% | 0.9640 | 0.9910 | 0.9930 | Evaluated |
| 8 | K-Nearest Neighbors (KNN) | 95.60% | 0.9610 | 0.9910 | 0.9890 | Evaluated |
| 9 | Logistic Regression | 93.40% | 0.9410 | 0.9430 | 0.9270 | Baseline |
| 10 | Gaussian Naive Bayes | 60.50% | 0.4540 | 0.2920 | 0.9970 | Inadequate |

> **Why Gradient Boosting was selected:**
> In cybersecurity threat intelligence, **Recall** is critical: a false negative (classifying a phishing link as safe) can compromise an entire organization. Gradient Boosting achieved a high recall of **98.87%** with an F1 score of **0.9772**, minimizing false negatives while maintaining low false-alarm rates.

### Production Confusion Matrix (2,211 Unseen Test Samples)

| Actual \ Predicted | Phishing (-1) | Legitimate (1) | Total |
| :--- | :---: | :---: | :---: |
| **Phishing (-1)** | **933** *(True Negatives)* | **43** *(False Positives)* | 976 |
| **Legitimate (1)** | **14** *(False Negatives)* | **1,221** *(True Positives)* | 1,235 |

- **True Positive Rate / Recall**: $1221 / (1221 + 14) = 98.87\%$
- **Precision**: $1221 / (1221 + 43) = 96.60\%$
- **Overall Accuracy**: $(1221 + 933) / 2211 = 97.42\%$

### Top Feature Importances (Gini Impurity Reduction)

```
HTTPS Status              [████████████████████████████████████] 69.66%
Anchor URL Ratio          [███████                             ] 13.22%
Website Traffic Rank      [██                                  ]  4.14%
Links in Script Tags      [██                                  ]  3.27%
Prefix-Suffix Hyphen      [█                                   ]  2.41%
Subdomain Depth           [█                                   ]  1.19%
Links Pointing to Page    [                                    ]  0.95%
Server Form Handler (SFH) [                                    ]  0.83%
Google Index Presence     [                                    ]  0.76%
Domain Registration Length[                                    ]  0.54%
```

---

## 🧩 Feature Engineering Pipeline (30 Features)

PhishGuard AI analyzes URLs using a comprehensive **30-dimensional feature vector** computed by [`feature.py`](feature.py). Each feature maps to a standard security indicator value:
- `+1`: **Legitimate / Safe Characteristic**
- `0`: **Suspicious / Ambiguous Indicator**
- `-1`: **Anomalous / Phishing Indicator**

### 1. URL Structure & Lexical Attributes
1. **Raw IP Address Host**: Checks whether the URL bypasses domain naming using direct IPv4/IPv6 literals (e.g. `http://192.168.1.1/login`).
2. **Long URL Length**: Phishing attackers conceal target domains using excessively long query strings ($\ge 75$ chars $\to$ Phishing, $54-75$ chars $\to$ Suspicious).
3. **URL Shortening Services**: Detects redirections via services such as `bit.ly`, `tinyurl.com`, `t.co`, and `ow.ly`.
4. **Symbol `@` Presence**: Detects credential-masking characters that cause browsers to disregard everything before the `@` symbol.
5. **Redirecting Double Slash (`//`)**: Inspects whether `//` appears after the 7th character, redirecting users to a rogue destination.
6. **Prefix/Suffix Hyphen (`-`)**: Analyzes domain hyphenation used to mimic legitimate entities (e.g., `paypal-security-update.com`).
7. **Subdomain Nesting**: Counts subdomain depth ($\ge 3$ subdomains indicates suspicious multi-tier redirection).
8. **HTTPS Certificate Validation**: Verifies SSL/TLS encryption presence and trusted Certificate Authority (CA) issuers.
9. **Non-Standard Ports**: Flags open services on non-standard ports (ports outside 80, 443, 8080).
10. **HTTPS in Domain Segment**: Identifies deceptive domain names containing the substring `https` (e.g., `https-verify-login.com`).
11. **Abnormal URL Structure**: Checks whether the hostname does not match the WHOIS identity.

### 2. Content & DOM Exfiltration Features
12. **Favicon Origin Check**: Flags favicons hosted on external domains, which often indicates cloned brand templates.
13. **Request URL Ratio**: Computes the percentage of external image, audio, and anchor tags pointing away from the base domain.
14. **Anchor URL Ratio**: Evaluates links inside `<a>` tags pointing to `javascript:void(0)`, `#`, or external hosts.
15. **Links in `<script>` & `<link>` Tags**: Analyzes external script dependencies and asset exfiltration sources.
16. **Server Form Handler (SFH)**: Flags form action handlers that are empty (`""`), `about:blank`, or submit credentials to foreign endpoints.
17. **Info Email Submission (`mailto:`)**: Detects forms configured to transmit captured credentials directly to an email inbox.
18. **Website Forwarding / Redirect Count**: Measures internal redirect hops ($\ge 4$ hops flags automated redirection cloaking).
19. **Status Bar Hijacking (`onmouseover`)**: Detects JavaScript handlers that disguise real link destinations in the browser status bar.
20. **Disabled Right Click**: Flags event listeners preventing users from viewing page source code (`event.button==2`).
21. **Popup Window Abuse**: Flags deceptive popup modals demanding credential re-entry.
22. **Iframe Redirection**: Identifies hidden or zero-pixel `<iframe>` tags used to embed phishing overlays.

### 3. Domain Reputation & Network Intelligence
23. **Domain Registration Length**: Flags newly minted domains with lifespans under 1 year.
24. **Age of Domain**: Assesses historical domain existence via WHOIS records ($< 6$ months flags threat indicators).
25. **DNS Record Verification**: Verifies valid DNS A, AAAA, and MX records.
26. **Website Traffic Rank**: Evaluates Alexa / Tranco global traffic rank (unranked domains receive risk penalties).
27. **PageRank Score**: Evaluates search visibility and authoritative link graphs.
28. **Google Index Presence**: Cross-references if the domain is indexed in search engine results.
29. **Backlink Count**: Checks volume of legitimate external websites linking to the domain.
30. **Statistical Blacklist Reporting**: Cross-references top threat intelligence feeds and IP reputation datasets.

---

## ✉️ Heuristic Email Threat Analyzer

Phishing attacks frequently arrive via sophisticated spear-phishing or business email compromise (BEC) campaigns. The built-in **Email Threat Scanner** ([`email_scanner.py`](email_scanner.py)) evaluates email headers and text bodies:

```
                               ┌─────────────────────────────────┐
                               │  Email Threat Scanner Engine    │
                               └────────────────┬────────────────┘
                                                │
         ┌──────────────────────────────┬───────┴──────────────────────┬──────────────────────────────┐
         ▼                              ▼                              ▼                              ▼
┌──────────────────┐          ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│ Sender Identity  │          │  Psychological   │           │ Credential & Fin │           │  Embedded Link   │
│ & Domain Spoofing│          │  Urgency Triggers│           │  Data Extraction │           │  Deobfuscation   │
└──────────────────┘          └──────────────────┘           └──────────────────┘           └──────────────────┘
• Free mail provider          • Artificial 24h   • Password, PIN, &             • Direct IP links
  impersonating enterprise      deadlines          SSN solicitations              in email body
  brands (e.g. PayPal on      • "Security alert" • Crypto / gift-card           • URL shortener
  @gmail.com)                   manufactured       wire transfer requests         redirection
• Malformed headers             panic            • Impersonal greetings           cloaking
```

### Threat Scoring Logic
- **`0.0 - 24.9%` $\to$ SAFE**: Sender authenticated, neutral wording, standard links.
- **`25.0 - 49.9%` $\to$ SUSPICIOUS**: Detected urgency keywords or impersonal greetings.
- **`50.0 - 100.0%` $\to$ PHISHING**: Brand spoofing detected, credential harvesting triggers, or raw IP links found.

---

## 🛡️ Defensive Engineering & Security Safeguards

PhishGuard AI implements defensive engineering controls to maintain security during scanning:

### 1. Automated URL Defanging
When handling active malware domains, accidental clicks can compromise analyst workstations. PhishGuard automatically transforms all target URLs into safe, non-clickable defanged strings before UI display or database storage:
- `https://evil-phish.com/login` $\longrightarrow$ `hxxps[://]evil-phish[.]com/login`
- `http://192.168.1.1` $\longrightarrow$ `hxxp[://]192[.]168[.]1[.]1`

### 2. SSRF (Server-Side Request Forgery) Guard
To prevent threat actors from utilizing the scanning backend as a proxy to probe internal enterprise networks, [`feature.py`](feature.py) executes pre-flight address validation:
```python
def is_private_or_loopback(host: str) -> bool:
    """Blocks loopback, RFC 1918 private, link-local, and reserved IP lookups."""
    # Checks 127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.
```
If an internal or private address is detected, external HTTP requests and socket resolutions are bypassed, and the submission is flagged with an SSRF alert indicator.

---

## 💻 Interactive Web Command Center

The web dashboard is organized into five specialized modules:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  🛡️ PhishGuard AI v2.0 ML     [● Gradient Boosting Active (97.4% Acc)]   [Theme: 🎨 ▾] │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  [ 🔍 URL Threat Scanner ]  [ ✉️ Email Analyzer ]  [ 📋 Audit Trail ]  [ 📊 Metrics ]   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   Target URL: [ https://paypal-security-verify.net/login          ] [ SCAN THREAT ⚡ ] │
│                                                                                        │
│   ┌──────────────────────────┐  ┌──────────────────────────────────────────────────┐  │
│   │     VERDICT: PHISHING    │  │ Defanged URL: hxxps[://]paypal-security-verify...│  │
│   │   Risk Score: 94.6%      │  │ SSRF Protection: Verified (Public Network)       │  │
│   │   Safety Score: 5.4%     │  │ Total Threat Flags: 6 Danger Indicators          │  │
│   └──────────────────────────┘  └──────────────────────────────────────────────────┘  │
│                                                                                        │
│   EXPLAINABLE AI DIAGNOSTICS:                                                          │
│   [🔴 Danger] Hyphenated Domain Spoofing — Mimics authentic brand with deceptive affixes│
│   [🔴 Danger] Low Domain Age — Domain was registered less than 14 days ago             │
│   [🔴 Danger] External Form Submission — Captures login credentials to unknown host    │
│   [🟡 Warn]   Unranked Web Traffic — Domain not listed in global top-1M rank index     │
│   [🟢 Safe]   Valid SSL Encryption — Utilizes standard TLS handshake                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **URL Threat Scanner**: Real-time URL evaluation with dynamic risk/safety dials, defanged copy utilities, and collapsible XAI indicators.
2. **Email Threat Analyzer**: Live textarea analysis with keyword highlighting and threat breakdown.
3. **Scan Audit Trail**: SQLite-powered forensic records with instant search, verdict filtering, and one-click database purge.
4. **AI Model Metrics Dashboard**: Visual display of accuracy, F1 score, precision, recall, live confusion matrix, and top-10 feature importance rankings.
5. **Cybersecurity Guide**: Reference material covering modern phishing evasion tactics and threat classification.

---

## 📡 RESTful API Reference

PhishGuard AI provides a RESTful JSON API for programmatic integration with security tools and SIEM workflows.

### 1. Scan URL
**Endpoint:** `POST /api/scan`  
**Content-Type:** `application/json`

#### Request Payload
```json
{
  "url": "https://secure-apple-id-verify.com"
}
```

#### Response Payload (200 OK)
```json
{
  "success": true,
  "scan_id": 42,
  "url": "http://secure-apple-id-verify.com",
  "raw_input": "https://secure-apple-id-verify.com",
  "defanged_url": "hxxps[://]secure-apple-id-verify[.]com",
  "risk_score": 96.8,
  "safety_score": 3.2,
  "verdict": "PHISHING",
  "threat_count": 5,
  "is_ssrf_risk": false,
  "indicators": [
    {
      "name": "Prefix-Suffix Hyphen",
      "category": "URL Structure & Lexical",
      "value": -1,
      "status": "danger",
      "title": "Hyphenated Domain Deception",
      "detail": "Domain uses prefix-suffix hyphenation mimicking established brands."
    }
  ]
}
```

---

### 2. Scan Email Content
**Endpoint:** `POST /api/scan-email`  
**Content-Type:** `application/json`

#### Request Payload
```json
{
  "sender": "support@paypal-notice-update.com",
  "subject": "URGENT: Your account has been suspended within 24 hours!",
  "body": "Dear customer, your account has been locked. Verify your password and enter your social security number immediately at http://192.168.1.50/verify"
}
```

#### Response Payload (200 OK)
```json
{
  "success": true,
  "sender": "support@paypal-notice-update.com",
  "subject": "URGENT: Your account has been suspended within 24 hours!",
  "risk_score": 85.0,
  "safety_score": 15.0,
  "verdict": "PHISHING",
  "detected_urls": ["http://192.168.1.50/verify"],
  "indicators": [
    {
      "type": "danger",
      "category": "Psychological Manipulation",
      "title": "Artificial Urgency & Coercion",
      "detail": "Uses high-pressure tactics demanding immediate compliance before penalties."
    },
    {
      "type": "danger",
      "category": "Payload & Intent",
      "title": "Direct Credential / Financial Solicitation",
      "detail": "Solicits highly confidential security credentials directly via email or form."
    }
  ]
}
```

---

### 3. Retrieve Scan History
**Endpoint:** `GET /api/history?limit=50`

#### Response Payload (200 OK)
```json
{
  "success": true,
  "stats": {
    "total_scans": 128,
    "phishing_count": 48,
    "safe_count": 72,
    "suspicious_count": 8
  },
  "history": [
    {
      "id": 42,
      "url": "http://secure-apple-id-verify.com",
      "defanged_url": "hxxps[://]secure-apple-id-verify[.]com",
      "risk_score": 96.8,
      "safety_score": 3.2,
      "verdict": "PHISHING",
      "threat_count": 5,
      "created_at": "2026-10-11 08:30:15"
    }
  ]
}
```

---

### 4. Fetch AI Model Metrics
**Endpoint:** `GET /api/metrics`

#### Response Payload (200 OK)
```json
{
  "success": true,
  "metrics": {
    "accuracy": 0.9742,
    "f1_score": 0.9772,
    "precision": 0.966,
    "recall": 0.9887,
    "total_test_samples": 2211,
    "confusion_matrix": {
      "tp": 1221,
      "fp": 43,
      "tn": 933,
      "fn": 14
    },
    "feature_importances": [
      { "name": "HTTPS", "importance": 0.6966, "percentage": 69.66 },
      { "name": "AnchorURL", "importance": 0.1322, "percentage": 13.22 }
    ]
  }
}
```

---

## 📂 Project Directory Structure

```
PhishGuard-AI/
├── .gitignore                 # Excludes environments, caches, and OS metadata
├── LICENSE                    # MIT Open Source License
├── Procfile                   # Cloud PaaS production execution command
├── README.md                  # Comprehensive architectural documentation
├── requirements.txt           # Python dependency definitions
├── app.py                     # Primary Flask web server & REST API controller
├── train.py                   # Automated model training and serialization script
│
├── core/                      # Core backend architecture & intelligence services
│   ├── __init__.py            # Python package initialization
│   ├── database.py            # SQLite database management & forensic query abstraction
│   ├── email_scanner.py       # Heuristic email threat detection engine
│   ├── feature.py             # 30-feature extraction pipeline, SSRF guard & defanging
│   └── metrics_service.py     # Model performance evaluator & telemetry aggregator
│
├── data/                      # Structured dataset & local persistence store
│   ├── phishing.csv           # 11,055-sample benchmark training dataset
│   ├── phishguard.db          # SQLite relational database storing historical scans
│   └── test-url.txt           # Verified adversarial test URLs for validation
│
├── models/                    # Serialized machine learning models & telemetry cache
│   ├── metrics_cache.json     # Precomputed evaluation telemetry for fast dashboard loading
│   └── model.pkl              # Production Gradient Boosting classifier binary
│
├── notebooks/                 # Jupyter research & exploratory data analysis (EDA)
│   └── Phishing URL Detection.ipynb # Model experimentation & benchmark notebook
│
├── static/                    # Frontend assets & client runtime
│   ├── app.js                 # Interactive dashboard controller & animations
│   ├── styles.css             # Unified CSS design system & multi-theme variables
│   ├── favicon.ico            # Favicon
│   ├── logo.png               # PhishGuard AI primary branding logo
│   └── img/                   # Documentation assets & media
│
└── templates/                 # Server-rendered HTML views
    └── index.html             # Multi-tab responsive command center interface
```

---

## 🚀 Quickstart & Installation Guide

### Prerequisites
- **Python**: Version `3.8` or higher
- **Package Manager**: `pip`
- **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/harshil51/PishGuard-AI.git
cd PishGuard-AI
```

### 2. Create and Activate a Virtual Environment
- **Windows (PowerShell):**
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
- **Linux / macOS:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Development Server
```bash
python app.py
```

The application will start locally:
```
 * Serving Flask app 'app'
 * Environment: production
 * Debug mode: on
 * Running on http://127.0.0.1:5000 (Press CTRL+C to quit)
```
Open **`http://127.0.0.1:5000`** in your browser to access the dashboard.

---

## 🛠️ Model Training & Serialization

The production Gradient Boosting classifier can be retrained on updated datasets using [`train.py`](train.py):

```bash
python train.py
```

**Training Output:**
```
Loading dataset: data/phishing.csv ...
Dataset Split: 8844 training samples, 2211 test samples across 30 features.
Training GradientBoostingClassifier (max_depth=4, learning_rate=0.7)...

--- Model Evaluation Results ---
Test Accuracy : 97.42%
F1 Score      : 0.9772
Precision     : 0.9660
Recall        : 0.9887

Trained model successfully serialized and saved to: models/model.pkl
```

---

## 🚢 Production Deployment

For enterprise production environments, run the application using a WSGI server like **Gunicorn**:

```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 app:app
```

### Deploying to Heroku / Render / Railway
This repository includes a [`Procfile`](Procfile) configured for immediate container deployment:
```text
web: gunicorn app:app
```

---

## 👨‍💻 Author & Acknowledgments

**Harshil Bhagora**  
- 🐙 GitHub: [@harshil51](https://github.com/harshil51)  
- 📧 Email: [harshilbhagora5@gmail.com](mailto:harshilbhagora5@gmail.com)  
- 📂 Repository: [harshil51/PishGuard-AI](https://github.com/harshil51/PishGuard-AI)

Contributions, issues, and feature requests are welcome! Feel free to open a pull request or issue ticket on GitHub.

---

## 📜 License

This project is licensed under the **[MIT License](LICENSE)**.

---

<p align="center">
  ⭐ <strong>If you found PhishGuard AI useful, please consider starring the repository on GitHub!</strong> ⭐
</p>

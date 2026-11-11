AI-Powered Email Threat Detection, Geolocation & Digital Forensic Intelligence Platform
**Detect. Investigate. Trace. Protect.**

An intelligent cybersecurity platform that goes beyond phishing detection to investigate suspicious emails, trace digital infrastructure, correlate threats, and generate forensic intelligence.

![Status](https://img.shields.io/badge/Status-Under%20Development-orange) ![Frontend](https://img.shields.io/badge/Frontend-React%20%7C%20Vite-blue) ![Backend](https://img.shields.io/badge/Backend-Node.js%20%7C%20Express-green) ![AI](https://img.shields.io/badge/AI-Python%20%7C%20FastAPI-purple) ![Database](https://img.shields.io/badge/Database-PostgreSQL-blue)

## 📌 Overview

**CyberLens** is an AI-assisted email threat detection and digital forensic intelligence platform designed to identify, analyze, and investigate potentially malicious emails.

Traditional email security systems primarily focus on classifying emails as legitimate or malicious. However, identifying a phishing email is only the beginning of a cybersecurity investigation.

CyberLens takes a deeper approach by combining email header forensics, AI-based threat detection, IP geolocation, domain intelligence, URL analysis, and digital evidence preservation into a unified investigation platform.

It helps security analysts understand:
- Who potentially sent the suspicious email?
- Are the email authentication checks valid?
- Are the sender and Reply-To addresses consistent?
- What IP addresses, URLs, and domains are involved?
- What infrastructure did the email travel through?
- Are there connections to known malicious indicators?
- Why was the email classified as suspicious?
- What evidence can be preserved for further investigation?

**Core Concept: We don't just detect malicious emails. We investigate them.**

## 🎯 Problem Statement

Email remains one of the most common attack vectors for cyber threats, including phishing, impersonation, credential theft, and business email compromise.

Existing detection approaches may identify suspicious emails but often provide limited visibility into the underlying infrastructure, sender authenticity, threat relationships, and forensic evidence.

Security analysts need a unified solution that combines detection, investigation, threat intelligence, and evidence analysis.

## 💡 Our Solution

CyberLens provides a multi-layer forensic investigation engine that processes suspicious emails and extracts meaningful security intelligence.

The platform combines:
- AI-assisted phishing and social engineering detection.
- Email header and authentication analysis.
- IP address and domain intelligence.
- Approximate geographical infrastructure mapping.
- Threat indicator extraction and correlation.
- Evidence preservation and forensic reporting.

Rather than relying on a single AI prediction, CyberLens combines deterministic security checks with AI-assisted reasoning to provide explainable investigation results.

## 🚀 Key Features

### 1. AI-Based Email Threat Detection
- Phishing email classification.
- Sender impersonation detection.
- Business Email Compromise indicators.
- Social engineering and urgency detection.
- Suspicious content and credential harvesting analysis.
- Explainable AI findings.
- Threat severity and risk assessment.

### 2. Advanced Email Header Forensics
- Email metadata extraction.
- Sender and recipient analysis.
- Reply-To and Return-Path mismatch detection.
- Received-header analysis.
- SMTP routing reconstruction.
- SPF, DKIM, and DMARC result analysis.
- Suspicious timestamp and header anomaly detection.

### 3. IP Geolocation & Infrastructure Intelligence
- IP address extraction.
- Approximate geographical location mapping.
- Country, region, and city information where available.
- ASN and ISP identification.
- Hosting provider identification.
- VPN, proxy, and Tor indicators where supported.
- IP reputation and abuse intelligence.

*Geolocation indicates approximate network infrastructure location, not the sender's exact physical location.*

### 4. Threat Intelligence & IOC Extraction
- Suspicious URL identification.
- Domain reputation analysis.
- IP reputation analysis.
- WHOIS and DNS intelligence.
- Extraction of Indicators of Compromise (IOCs).
- Integration with external threat intelligence providers.
- Historical indicator correlation.

### 5. Digital Forensic Investigation
- Investigation and case management.
- Secure evidence collection.
- SHA-256 evidence hashing.
- Chain-of-custody tracking.
- Investigation activity logs.
- Evidence timeline.
- Analyst notes and investigation records.

### 6. Threat Relationship Visualization
Interactive visualization of relationships between:

`Email → Sender → Domain → IP Address → ASN → Threat Intelligence`

Helps analysts understand connections between suspicious indicators and potentially related infrastructure.

### 7. AI Forensic Assistant
- Investigation summaries.
- Explainable threat findings.
- Contextual investigation assistance.
- Recommended investigation actions.
- Evidence-based analysis.

### 8. Forensic Report Generation
Generate structured investigation reports containing:
- Email metadata.
- Header analysis.
- Authentication results.
- AI threat assessment.
- IP and domain intelligence.
- Extracted indicators.
- Evidence hashes.
- Investigation timeline.
- Analyst conclusions.

## 🔄 Investigation Workflow

CyberLens follows a structured investigation pipeline:

```text
       EMAIL INPUT
            |
            ▼
       EMAIL PARSER
            |
            ▼
    HEADER FORENSICS
            |
            ▼
   SPF / DKIM / DMARC
            |
            ▼
     IOC EXTRACTION
            |
            ▼
    URL & DOMAIN ANALYSIS
            |
            ▼
    IP INTELLIGENCE
            |
            ▼
    GEOLOCATION ANALYSIS
            |
            ▼
     AI THREAT ANALYSIS
            |
            ▼
     RISK ASSESSMENT
            |
            ▼
  INVESTIGATION DASHBOARD
            |
            ▼
    FORENSIC REPORT
```

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Frontend | React.js, Vite, JavaScript |
| UI & Styling | Tailwind CSS, shadcn/ui |
| Backend | Node.js, Express.js |
| Database | PostgreSQL |
| ORM | Prisma |
| AI Service | Python, FastAPI, Pydantic |
| AI Integration | LLM API, optional DistilBERT |
| Data Visualization | Recharts, React Flow |
| Geolocation | Leaflet, React-Leaflet |
| Authentication | JWT, bcrypt |
| API Communication | Axios, REST APIs |
| Development Tools | Git, GitHub, VS Code |

## 🏗️ System Architecture

```text
              FRONTEND
           React + Vite
                 |
                 ▼
           REST API LAYER
           Node.js + Express
                 |
                 ▼
        INVESTIGATION ENGINE
                 |
       ┌─────────┼──────────┐
       ▼         ▼          ▼
   EMAIL       THREAT       AI
  FORENSICS   INTELLIGENCE ANALYSIS
       |         |          |
       └─────────┼──────────┘
                 |
                 ▼
          PostgreSQL
            Prisma
                 |
                 ▼
       INVESTIGATION RESULTS
                 |
       ┌─────────┼──────────┐
       ▼         ▼          ▼
   DASHBOARD   THREAT     FORENSIC
              GRAPH       REPORTS
```

## 🌐 External Intelligence Integrations

The platform is designed to support integration with cybersecurity intelligence services, including:

| Service | Purpose |
|---|---|
| VirusTotal | URL, domain and file reputation |
| AbuseIPDB | IP abuse intelligence |
| URLhaus | Malicious URL intelligence |
| Google Safe Browsing | Unsafe URL detection |
| IPinfo | IP geolocation and network information |
| WHOIS / RDAP | Domain registration intelligence |

External services may require API keys and are integrated through backend service adapters.

## 🔮 Future Scope

- Real-time email threat monitoring.
- Advanced phishing detection models.
- Automated campaign correlation.
- Enhanced infrastructure relationship mapping.
- Advanced anomaly detection.
- Improved AI forensic investigation assistant.
- SOC and SIEM integrations.
- Automated investigation workflows.
- Advanced threat intelligence visualization.

## 🔒 Security & Privacy

CyberLens is designed with security and forensic evidence integrity as core principles.

- Secure evidence storage and access control.
- SHA-256 evidence integrity verification.
- Protected environment variables and API credentials.
- Safe email and attachment handling.
- Input validation and API security.
- No automatic execution of suspicious attachments.
- Controlled third-party intelligence integrations.

## ⚠️ Disclaimer

CyberLens is intended for educational, research, and authorized cybersecurity investigation purposes.

All investigations should be performed using emails, systems, and digital evidence that the user is authorized to access.

AI-generated findings and threat scores should be treated as analytical assistance and verified against supporting evidence.

---

## 👩‍💻 Developer

**Mahi Rajput**

B.Tech — Computer Science & Business Systems

GitHub: [@mahiiyyy](https://github.com/mahiiyyy)

---

<p align="center">
  **CYBERLENS**
  <br/>
  Detection is only the beginning. 🔐
</p>
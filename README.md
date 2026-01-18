# 📧 Phishing Email Detection & IOC Analysis (SOC Project)

## 📌 Project Overview
This project demonstrates a real-world Security Operations Center (SOC) phishing email investigation workflow.  
It focuses on identifying malicious email campaigns through header analysis, authentication validation, URL behavior analysis, **attachment analysis**, and IOC extraction — closely mirroring real SOC alert triage and escalation procedures.


---

## 🎯 Objectives
- Detect phishing indicators in suspicious emails
- Analyze raw email headers and mail flow
- Validate SPF, DKIM, and DMARC authentication results
- Identify sender spoofing and trusted infrastructure abuse
- Safely analyze URLs and redirect chains
- **Analyze email attachments using hash-based reputation checks**
- Extract and document Indicators of Compromise (IOCs)
- Produce SOC-ready incident documentation

---

## 🛠 Tools & Platforms Used

| Category | Tools |
|-------|------|
| Email Client | Microsoft Outlook |
| Raw Email Analysis | Notepad++ |
| Header Analysis | mailheader.org, MXToolbox |
| Attachment Handling | Hashing utilities (SHA256) |
| URL Behavior Analysis | urlscan.io |
| Threat Intelligence | VirusTotal |
| Documentation | Markdown (GitHub) |

---

## 🧠 Investigation Methodology

### 1️⃣ Initial Email Triage
- Reviewed reported emails for:
  - Urgent or fear-based language
  - Generic greetings
  - Brand impersonation
  - Unexpected attachments
- No links or attachments were opened or executed

---

### 2️⃣ Raw Header Analysis
- Extracted full email headers
- Analyzed:
  - Sender IP and routing path
  - Authentication results (SPF, DKIM, DMARC, CompAuth)
  - Domain inconsistencies

---

### 3️⃣ Authentication Validation
- Evaluated authentication controls:
  - **FAIL:** Strong indicator of spoofing or unauthorized infrastructure
  - **PASS:** Further investigated for trusted SaaS abuse

> ⚠️ Authentication success does **not** guarantee legitimacy

---

### 4️⃣ URL & Redirect Analysis
- Analyzed embedded URLs using passive tools
- Identified:
  - Redirect chains
  - Tracking domains
  - Final malicious landing pages

---

### 5️⃣ Attachment Analysis 
- If an email contained an attachment:
  - The attachment was **extracted without execution**
  - File metadata and extension were reviewed
  - **Cryptographic hash (SHA-256) was generated**
  - The hash was submitted to **VirusTotal** for reputation analysis
- Results were used to:
  - Identify known malware
  - Detect phishing document droppers
  - Confirm malicious or suspicious classification

> ✔ No attachments were executed or detonated locally

---

### 6️⃣ Threat Intelligence Correlation
- Validated all extracted indicators using VirusTotal
- Correlated:
  - Hash reputation
  - Domain/IP detections
  - Historical campaign data

---

### 7️⃣ IOC Extraction & Documentation
- Extracted and categorized:
  - IP addresses
  - Domains
  - URLs
  - Email addresses
  - **File hashes (when applicable)**
- Documented in **SOC-ready Markdown format**

---

## 🧪 Investigated Cases

| Case | Description |
|----|------------|
| Case 01 | Phishing via Mailgun infrastructure with redirect obfuscation |
| Case 02 | Crypto phishing abusing trusted SaaS infrastructure |
| Case 03 | Microsoft brand impersonation with authentication failures |

---

## 🧬 MITRE ATT&CK Mapping

| Tactic | Technique |
|------|----------|
| Initial Access | T1566.001 – Spearphishing Email |
| Initial Access | T1566.002 – Phishing via Link |
| Initial Access | T1566.001 – Phishing Attachment |
| Credential Access | T1056 – Credential Harvesting |
| Defense Evasion | T1585 – Spoofed Infrastructure |
| Resource Development | T1583 – Domain Acquisition |

---

## 🚨 SOC Response & Recommendations

### Immediate Actions
- Block confirmed malicious IPs, domains, and file hashes
- Remove malicious emails and attachments from user mailboxes
- Monitor hash reappearance across endpoints and SIEM

### Detection Improvements
- Alert on:
  - Attachment + urgency-based email patterns
  - Office/PDF attachments from external senders
  - Known malicious hashes
  - Brand impersonation + DMARC failures

### User Awareness
- Never open unexpected email attachments
- Security teams do not send executable files via email

---

## ⚠️ Disclaimer
This project was conducted in a controlled lab environment using **passive analysis only**.  
No malicious links, attachments, or payloads were executed.

Indicators are documented strictly for **defensive security and educational purposes**.

---

## 👤 Author
**Asim**  

---




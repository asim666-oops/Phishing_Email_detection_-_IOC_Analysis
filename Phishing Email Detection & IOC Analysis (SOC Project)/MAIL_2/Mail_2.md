# SOC Phishing Email Investigation Project

## Project Overview

As part of my SOC analyst training, I conducted a phishing email investigation to simulate a real-world Security Operations Center (SOC) incident response scenario.

This project demonstrates my ability to:

- Analyze suspicious emails
- Perform header and infrastructure analysis
- Investigate URL redirection chains
- Identify Indicators of Compromise (IOCs)
- Map findings to MITRE ATT&CK
- Provide actionable SOC recommendations

---

## Case Information

**Severity:** High  
**Final Verdict:** Confirmed Phishing  

---

## Executive Summary

I investigated an email with the subject:

**“Your wallet may get suspended”**

The email was reported as suspicious. Although it passed SPF, DKIM, and DMARC authentication checks, deeper analysis revealed clear malicious intent.

During my investigation, I identified:

- URL redirection abuse
- Infrastructure manipulation
- Sender identity mismatch
- Social engineering techniques targeting cryptocurrency users

The attacker abused a legitimate email marketing service (Kajabi/Mailgun) to distribute a phishing campaign themed around the Ethereum merge update, attempting to steal wallet credentials or seed phrases.

---

## Email Metadata Analysis

| Field | Value |
|-------|-------|
| From | rafia-khan@f.kajabimail.net |
| Reply-To | rafiakhan314@gmail.com |
| Return-Path | bounce+…@f.kajabimail.net |
| Subject | Your wallet may get suspended! |
| Sender IP | 143.55.229.223 |
| Sending Platform | Kajabi / Mailgun |

### Key Finding

There was a mismatch between the **From domain** and the **Reply-To address**, which is a common phishing indicator.

---

## Email Authentication Results

| Control | Result |
|----------|--------|
| SPF | PASS |
| DKIM | PASS |
| DMARC | PASS |
| CompAuth | PASS |

### Investigation Insight

Even though authentication passed, I determined that:

> Passing SPF/DKIM/DMARC does NOT guarantee email legitimacy.

Attackers often abuse trusted SaaS platforms to bypass email security controls.

---

## Header & Infrastructure Investigation

### Sender IP Analysis

- IP: 143.55.229.223  
- Tool Used: MXToolbox  
- Reputation: Clean  
- Mail Server: mail229-223.static.kajabimail.net  

The infrastructure was legitimate, which indicates the attacker leveraged trusted marketing services rather than compromised infrastructure.

---

## URL & Redirect Analysis (Critical Finding)

### Observed URL

```
http://email.f.kajabimail.net/
```

### Investigation Process

I analyzed the URL using multiple tools:

- VirusTotal → Clean (tracking/redirect domain)
- MXToolbox → No blacklist hits
- urlscan.io → Revealed malicious redirect

### Final Redirect IP Identified

- 34.162.239.211 (Malicious infrastructure)

### Redirect Chain Identified

```
User Clicks Email Link
        ↓
email.f.kajabimail.net (Legitimate Tracking Domain)
        ↓
HTTP Redirect
        ↓
34.162.239.211 (Malicious Phishing Server)
```

### Why This Attack Is Effective

- Initial domain appears trusted
- Malicious payload hosted separately
- Basic scanners only check first-layer domain
- Redirect-based evasion technique

---

## Email Content Analysis

### Social Engineering Indicators Identified

- Urgency: “Wallet may get suspended”
- Fear-based messaging: “You will lose all your assets”
- Deadline pressure
- Cryptocurrency theme targeting Ethereum users

### Technical Evasion Techniques Observed

- Unicode homoglyph characters (α, υ, κ)
- Large whitespace padding
- HTML obfuscation
- Generic greeting

---

## MITRE ATT&CK Mapping

| Technique | ID |
|------------|-----|
| Phishing via Link | T1566.002 |
| Credential Harvesting | T1056 |
| Initial Access (Social Engineering) | TA0001 |

---

## Indicators of Compromise (IOCs)

### Network IOCs

- 143.55.229.223  
- 34.162.239.211 (Malicious Redirect IP)

### Domain IOCs

- email.f.kajabimail.net  
- f.kajabimail.net  

### Email IOCs

- Reply-To: rafiakhan314@gmail.com  
- Subject: Your wallet may get suspended!  

---

## Final SOC Verdict

After completing header analysis, URL redirection tracing, infrastructure review, and content inspection, I confirmed:

✔ Confirmed Phishing Email  
✔ High Confidence Malicious Intent  
✔ Credential Harvesting Attempt  
✔ Abuse of Legitimate Email Infrastructure  

---

## Recommended SOC Actions

### Immediate Defensive Actions

- Block malicious IP: 34.162.239.211
- Monitor redirect activity from email.f.kajabimail.net
- Quarantine similar campaign emails

### Detection Engineering Improvements

Create alerts for:

- From / Reply-To mismatch
- Crypto-related urgency keywords
- Redirect-based tracking domains
- Unicode obfuscation patterns

### User Awareness Recommendations

- Cryptocurrency platforms do not request upgrades via email
- Wallet updates occur only inside official applications

---

## Project Conclusion

This investigation demonstrates how modern phishing campaigns bypass traditional authentication controls by abusing trusted marketing infrastructure and redirect-based evasion techniques.

Through this project, I applied real SOC analyst methodology:

- Log and header analysis
- Threat intelligence validation
- IOC identification
- MITRE ATT&CK mapping
- Defensive recommendations

This project reflects practical L1 SOC investigation capability.

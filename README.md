# SOC Project: Alerts to Adversaries — Capstone Report

## Overview
This repository documents my work analyzing multiple Microsoft Sentinel alerts as part of a simulated enterprise compromise in the **MARVEL.LOCAL** domain. The investigation involved identifying, correlating, and remediating attacker activity across two workstations — **Asgard-Wrkstn** and **Wakanda-Wrkstn** — while mapping each behavior to the **MITRE ATT&CK Framework**.

The project demonstrates my ability to:
- Investigate multi-stage alerts within Microsoft Sentinel.
- Use **KQL (Kusto Query Language)** to uncover and validate malicious activity.
- Correlate telemetry across hosts to rebuild a complete attack chain.
- Classify and recommend remediations for each stage of an intrusion.

---

## Attack Summary
On **October 9, 2025**, an attacker gained initial access through a malicious HTA file (*Receipt.hta*) opened by **marvel\\panther** on **Asgard-Wrkstn**. The attacker used built-in Windows tools (LOLBins) such as **mshta.exe**, **rundll32.exe**, and **PowerShell** to execute payloads, establish persistence, escalate privileges, and move laterally. Key stages included:

1. **Initial Access:** mshta.exe executed *Receipt.hta*, launching the first beacon.
2. **Persistence:** Created *WindowsUpdater* service (SYSTEM) and WMI Event Subscription (*rmm.exe*).
3. **Privilege Escalation:** Process injection from panther to thor context.
4. **Credential Access:** Mimikatz and Rubeus (Kerberoast) usage to harvest credentials.
5. **Lateral Movement:** PowerShell remoting via WinRM to Wakanda-Wrkstn.
6. **Domain Dominance:** DCSync replication abuse for domain credential extraction.
7. **Cleanup:** Event logs cleared to remove traces.

The full timeline and detailed MITRE mappings are available in [Summary_of_Findings.md](Summary_of_Findings.md).

---

## Tools and Technologies
- **Microsoft Sentinel** — Alert triage and investigation.
- **Kusto Query Language (KQL)** — Log correlation and threat hunting.
- **Windows Event Logs / JonMon Logs** — Host-level telemetry analysis.
- **MITRE ATT&CK Framework** — Technique classification.

---

## Key Insights
- Attack leveraged **LOLBins** to evade standard detection mechanisms.
- WMI and service creation persistence provided long-term footholds.
- Lateral movement and process injection demonstrated realistic domain compromise scenarios.
- Event log clearing emphasized attacker awareness and anti-forensic measures.

---

## Recommendations
- Improve **cross-host correlation** for alerts in Sentinel.
- Add detections for **service creation** in user temp directories.
- Monitor for **named pipe** C2 activity and WMI consumer persistence.
- Enforce **PowerShell execution policies** and **WinRM access control**.
- Alert on **Event ID 1102** (log clearing) and create baselines for legitimate activity.

---

## Repository Structure
```
SOC-Alerts-Analysis/
│
├── README.md                      # Project overview (this file)
├── Summary_of_Findings.md          # Full report with alert analysis and KQL queries
├── Alerts/                         # Individual alert breakdowns (optional)
├── Remediations/                   # Mitigation and response recommendations
└── Resources/                      # Attacker overview and reference materials
```

---

## Author
**Joe Greenwell**  
Cybersecurity Analyst | Microsoft Sentinel | Threat Detection & Response  
📧 josephgreenwell3@gmail.com  

---

## Acknowledgements
This project was completed as part of a SOC Analyst capstone simulation. Special thanks to the course instructors and peers who provided post-analysis attacker overviews for validation and learning.
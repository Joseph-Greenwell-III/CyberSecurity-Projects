# Alerts to Adversaries — Capstone Report

**Student Name:** Joe Greenwell  
**Date:** 10/18/2025  
**Domain:** MARVEL  
**Hosts Investigated:** Asgard-Wrkstn.marvel.local, Wakanda-Wrkstn.marvel.local  
**Users:** thor, panther  

---

## Scenario Overview

### Summary of the Attack Flow
On October 9, 2025, an attacker gained initial code execution on **Asgard-Wrkstn** when **marvel\\panther** opened *Receipt.hta*, triggering **mshta.exe** to execute the embedded script. This launched the first beacon running as **panther**. The attacker then uploaded **win-svc.exe** to `C:\Users\panther\AppData\Local\Temp\` and created a service named **WindowsUpdater** for persistence. This service executed under **SYSTEM**, creating a secondary beacon that communicated locally via named pipes.

While still operating as **panther**, the attacker extracted credential material from **LSASS** using **Mimikatz** and executed **Rubeus** to perform **Kerberoast** requests. These actions retrieved several credentials, including the password for **marvel\\thor**. However, the attacker did not use these harvested credentials directly—instead, they laterally moved to **Wakanda-Wrkstn** via **WinRM**, still as **panther**, and located a process already running under the **thor** context. By injecting into this process, they adopted **Thor’s** privileges.

Now operating as **Thor**, the attacker established **WMI Event Subscription** persistence to execute *rmm.exe* on boot, performed a **DCSync** operation to obtain domain credential data, and finally cleared event logs on both Asgard-Wrkstn and Wakanda-Wrkstn to remove evidence of compromise.

---

## Technical Details

### **Attack 1 – Initial Access: Malicious HTA Execution**
**User / Actor:** marvel\\panther (Asgard-Wrkstn)  
**Alert:** Capstone – Mshta Execution  
**MITRE ATT&CK Technique:** T1218.005 (System Binary Proxy Execution: Mshta)

**Observation:**
- *Receipt.hta* executed via **mshta.exe**, launching an embedded script and initiating the first beacon.

**Classification:** True Positive  
**Notes:**
- Detection analytics effective.  
- Consider additional coverage for suspicious HTA executions in user directories.

---

### **Attack 2 – Local & Domain Reconnaissance**
**User / Actor:** marvel\\panther (Asgard-Wrkstn)  
**Alert:** None  
**MITRE ATT&CK Technique:** T1087 (Account Discovery), T1069 (Permission Groups Discovery)

**Observation:**
- The attacker executed discovery commands (e.g., `whoami`, `net user`) to enumerate domain users and privileges.

**Helpful KQL Query:**
```kql
WindowsEvent
| where EventID == 4688
| where EventData.CommandLine contains "whoami" or EventData.CommandLine contains "net user"
```

**Classification:** Informational  
**Notes:**
- Adds context to early reconnaissance efforts not covered by Sentinel detections.

---

### **Attack 3 – Service Creation (Privilege Escalation + Persistence)**
**User / Actor:** marvel\\panther (Asgard-Wrkstn)  
**Alert:** None  
**MITRE ATT&CK Technique:** T1543.003 (Create or Modify System Process: Windows Service)

**Observation:**
- The attacker created a Windows service named **WindowsUpdater** to execute **win-svc.exe** from the user’s temp directory under SYSTEM privileges.

**Helpful KQL Query:**
```kql
WindowsEvent
| where EventID == 4697 and EventData.ServiceFileName contains "temp"
WindowsEvent
| where EventID == 8 and EventData.RegKeyPath contains "services" and EventData.Data contains "temp"
```

**Classification:** True Positive  
**Notes:**
- Indicates persistence and privilege escalation in one step.

---

### **Attack 4 – Privilege Escalation & Secondary Beacon (Named Pipe)**
**User / Actor:** SYSTEM (Asgard-Wrkstn)  
**Alert:** Capstone – CobaltStrike Named Pipes  
**MITRE ATT&CK Technique:** T1071.002 (Application Layer Protocol: Named Pipes)

**Observation:**
- Secondary beacon executed as SYSTEM via **win-svc.exe**, communicating locally through named pipes (`MSSE-1380-server`, `mojo.*`).

**Classification:** True Positive  
**Notes:**
- High-confidence beacon behavior; strong detection coverage for pipe-based C2 channels.

---

### **Attack 5 – Credential Access: LSASS Memory Access**
**User / Actor:** marvel\\panther (Asgard-Wrkstn)  
**Alert:** None  
**MITRE ATT&CK Technique:** T1003.001 (LSASS Memory)

**Observation:**
- The attacker accessed LSASS using **Mimikatz** to extract credential data.

**Helpful KQL Query:**
```kql
WindowsEvent
| where EventID == 4663 and EventData.ObjectName contains "lsass.exe"
```

**Classification:** True Positive  
**Notes:**
- Add LSASS access monitoring for non-system accounts.

---

### **Attack 6 – Credential Access: Kerberos Abuse (Rubeus / Kerberoast)**
**User / Actor:** marvel\\panther (Asgard-Wrkstn)  
**Alert:** Capstone – Rubeus executed via .NET  
**MITRE ATT&CK Technique:** T1558.003 (Kerberoasting)

**Observation:**
- Rubeus used to request service tickets for offline password cracking.

**Classification:** True Positive  
**Notes:**
- Alert correctly identified the tool execution but lacked full context for validation.

---

### **Attack 7 – Lateral Movement via WinRM**
**User / Actor:** marvel\\panther (Asgard-Wrkstn → Wakanda-Wrkstn)  
**Alert:** Capstone – Potential Lateral Movement via Network Logon Type  
**MITRE ATT&CK Technique:** T1021.002 (Remote Services: SMB/WinRM)

**Observation:**
- Lateral movement achieved through PowerShell remoting; encoded PowerShell script (`wmiper.ps1`) executed remotely.

**Classification:** True Positive  
**Notes:**
- Behaviorally accurate detection; could benefit from correlation with preceding privilege escalation activity.

---

### **Attack 8 – Privilege Escalation: Process Injection to Adopt Thor Context**
**User / Actor:** marvel\\panther (Asgard-Wrkstn)  
**Alert:** None  
**MITRE ATT&CK Technique:** T1055.001 (Process Injection)

**Observation:**
- The attacker injected into a process running as **marvel\\thor** to assume elevated privileges.

**Helpful KQL Query:**
```kql
WindowsEvent
| where Provider == "JonMon" and (EventID == 24 or EventID == 25 or EventID == 26)
| where EventData.SourceProcessIntegrityLevel != "Medium"
| project TimeGenerated, Computer, EventID, EventData.SourceProcessFilePath, EventData.SourceProcessUser, EventData.TargetProcessFilePath, EventData.TargetProcessUser
```

**Classification:** True Positive  
**Notes:**
- Advanced privilege escalation using process injection; limited by detection visibility.

---

### **Attack 9 – Persistence: WMI Event Subscription Installed**
**User / Actor:** marvel\\thor (Wakanda-Wrkstn)  
**Alert:** Capstone – WMI Event Subscription  
**MITRE ATT&CK Technique:** T1546.003 (Event Triggered Execution: WMI Event Subscription)

**Observation:**
- WMI event consumer created to persist **rmm.exe** execution at system startup.

**Classification:** True Positive  
**Notes:**
- Well-detected persistence method; strong alignment with ATT&CK coverage.

---

### **Attack 10 – Domain Dominance: DCSync / Replication Abuse**
**User / Actor:** marvel\\thor (Asgard-Wrkstn)  
**Alert:** Capstone – Possible DCSync  
**MITRE ATT&CK Technique:** T1003.006 (OS Credential Dumping: DCSync)

**Observation:**
- Domain controller replication requests observed, likely DCSync-related.  
- Incomplete data transfer but confirmed intent.

**Classification:** True Positive  
**Notes:**
- Strengthen correlation rules for replication activity and user role validation.

---

### **Attack 11 – Cleanup: Log Clearing**
**User / Actor:** marvel\\thor and marvel\\panther (Asgard-Wrkstn & Wakanda-Wrkstn)  
**Alert:** None  
**MITRE ATT&CK Technique:** T1070.001 (Indicator Removal: Clear Windows Event Logs)

**Observation:**
- Logs cleared using **wevtutil cl Security**; Event ID 1102 present in the Security channel.

**Helpful KQL Query:**
```kql
WindowsEvent
| where Channel == "Security" and EventID == 1102
```

**Classification:** True Positive  
**Notes:**
- Indicates attacker cleanup and anti-forensics awareness.

---

## Additional Notes and Recommendations
- Attack chain demonstrates effective use of **LOLBins** (rundll32, mshta, PowerShell) to bypass traditional defenses.
- Recommend increased **process correlation** and **cross-host event linking** for Sentinel rules.
- Strengthen PowerShell policies (`AllSigned`), enable **WinRM restrictions**, and alert on **new service creations** in non-standard directories.
- Implement baselines for **event log clearing (Event ID 1102)** and alert on deviations.

---

## Lessons Learned
This capstone scenario emphasized the importance of correlating multiple low-visibility alerts to reconstruct full intrusion chains. Each stage built on the previous, culminating in domain-level compromise and evidence removal. Strengthening visibility into persistence, process injection, and credential access behaviors remains key for improving detection fidelity across Microsoft Sentinel environments.


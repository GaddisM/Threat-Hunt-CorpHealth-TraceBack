
<img width="1024" height="1536" alt="ChatGPT Image Feb 19, 2026, 11_59_04 PM" src="https://github.com/user-attachments/assets/c1a78af5-35f9-4867-a368-a373b8273fcd" />

---

## Case Metadata

- **Case Name:** CorpHealth Privileged Automation Review  
- **Incident Classification:** Operations Activity Review (Pre-Incident → Confirmed Intrusion)  
- **Analyst Role:** Lead Threat Analyst  
- **Data Sources:**  
  - Microsoft Defender for Endpoint  
  - Azure Logs  
  - Endpoint Artifacts  
- **Primary Host:** CH-OPS-WKS02  
- **Investigation Period:** 2025-11-15 → 2025-12-09 

----
-----
## Executive Summary

This report documents a confirmed security incident involving unauthorized activity on a CorpHealth operational workstation (**CH-OPS-WKS02**). What initially appeared to be routine diagnostic and maintenance activity was determined, through structured threat hunting, to be the result of **credential compromise and malicious misuse of privileged access**.

The investigation identified that an external attacker successfully authenticated to the workstation using valid credentials associated with a privileged account. Following initial access, the attacker performed a sequence of actions consistent with a full intrusion lifecycle, including system reconnaissance, data collection, staging, attempted security control evasion, and persistence establishment.

Key findings include the creation of multiple diagnostic inventory files in CorpHealth-branded directories, indicating deliberate data staging for analysis or exfiltration. The presence of nearly identical files with different hashes across multiple directories strongly suggests iterative data processing rather than legitimate automation. Additional activity revealed suspicious registry modifications consistent with credential inspection or harvesting attempts.

The attacker attempted to weaken endpoint defenses by modifying Windows Defender exclusion settings, demonstrating clear intent to evade detection prior to executing higher-risk payloads. Although this action was blocked, it represents a critical escalation in attacker behavior. The investigation also confirmed the delivery of an external executable via an encrypted tunnel service, followed by persistence mechanisms leveraging scheduled tasks and startup folder placement.

Geolocation enrichment of attacker IP addresses indicates the activity originated from outside the organization’s expected operating regions. The timeline reconstruction shows deliberate, methodical actions rather than opportunistic or automated noise, reinforcing the conclusion that this was a targeted intrusion.

No evidence confirms successful data exfiltration; however, the attacker completed multiple preparatory stages required for such an outcome. The incident underscores the risks associated with credential exposure, over-privileged accounts, and trusted internal tooling being abused to blend malicious activity with legitimate operations.

This report provides a full technical reconstruction of the attack chain, mapped to MITRE ATT&CK, and includes detection opportunities and defensive lessons applicable to enterprise security operations.

------

## Investigation Methodology

This investigation followed a **hypothesis-driven threat hunting model**:

1. **Scope Definition** – Identify affected assets and timeframe  
2. **Baseline Validation** – Compare observed activity against known CorpHealth behavior  
3. **Behavioral Deviation Analysis** – Identify anomalies across process, file, registry, and network telemetry  
4. **Timeline Reconstruction** – Correlate events chronologically  
5. **Intent Determination** – Assess attacker objectives and tradecraft  
6. **Attribution Context** – Enrich with session metadata and geolocation  
7. **Closure & Synthesis** – Reconstruct full attack chain  


-----
## Scope and Environment

This investigation was conducted within a controlled corporate endpoint environment supporting internal operations and diagnostics.

### Organizational Context

- **Company Name:** CorpHealth
- **Business Function:** Internal endpoint diagnostics, operational monitoring, and maintenance
- **Environment Type:** Corporate IT Operations (On-Prem + Cloud-integrated)

### In-Scope Assets
The following assets were explicitly included in the scope of this investigation:
```kql
- **Endpoint:** CH-OPS-WKS02  
  - Role: Operations / Maintenance Workstation  
  - Operating System: Windows 10 Enterprise  
  - Usage Profile: Privileged diagnostics, automation tasks, maintenance scripting

- **User Accounts:**
  - `chadmin` (privileged account)
  - `ops.maintenance` (service / automation account)
  - `chad` (interactive user session observed during investigation)

- **Directories and Artifacts:**
  - `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\`
  - `C:\Users\*\AppData\Local\Temp\CorpHealth\`
  - Startup and persistence locations
  - Windows Registry (HKLM focus)
```
### Telemetry Sources
The investigation relied exclusively on native security telemetry:
```kql
- Microsoft Defender for Endpoint
  - DeviceProcessEvents
  - DeviceFileEvents
  - DeviceNetworkEvents
  - DeviceRegistryEvents
  - DeviceLogonEvents
- Defender geolocation enrichment (`geo_info_from_ip_address()`)

No external OSINT platforms or third-party forensic tools were used.
```
### Timeframe
```kql
- **Primary Investigation Window:**  
  `2025-11-21` → `2025-12-09`
- **Anchor Event:**  
  First confirmed suspicious logon at `2025-11-23T03:08:31Z`
```
### Out-of-Scope
The following were explicitly excluded from scope:
```kql
- Other CorpHealth endpoints not exhibiting related telemetry
- Email infrastructure and phishing analysis
- Network firewall logs outside Defender visibility
- Long-term attribution beyond geolocation enrichment

```
---
## Table of Contents

1. Executive Summary  
2. Scope & Environment Overview  
```kql
3. Investigation Overview  
   3.1 Case Context  
   3.2 Data Sources  
   3.3 Investigation Methodology  
```
4. Threat Hunt Timeline & Findings  
```kql
   4.1 Flag 0 – Scope Establishment & Device Identification  
   4.2 Flag 1 – Unique Maintenance Script Identification  
   4.3 Flag 2 – Initial Outbound Network Activity  
   4.4 Flag 3 – Beacon Destination Identification  
   4.5 Flag 4 – Successful Beacon Timestamp  
   4.6 Flag 5 – Primary Staging Artifact Creation  
   4.7 Flag 6 – File Hash Identification  
   4.8 Flag 7 – Secondary Staging Artifact Discovery  
   4.9 Flag 8 – Suspicious Registry Modification  
   4.10 Flag 9 – Unauthorized Scheduled Task Creation  
   4.11 Flag 10 – Registry-Based Persistence Attempt  
   4.12 Flag 11 – Privilege Escalation Event Timestamp  
   4.13 Flag 12 – Antivirus Exclusion Attempt  
   4.14 Flag 13 – Encoded PowerShell Command Execution  
   4.15 Flag 14 – Privilege Token Modification Process  
   4.16 Flag 15 – Compromised Token Identity  
   4.17 Flag 16 – External Tool Ingress  
   4.18 Flag 17 – External Download Source Identification  
   4.19 Flag 18 – Execution of Staged Binary  
   4.20 Flag 19 – External IP Contacted by Malicious Tool  
   4.21 Flag 20 – Startup Folder Persistence  
   4.22 Flag 21 – Remote Session Source Device  
   4.23 Flag 22 – Remote Session Source IP  
   4.24 Flag 23 – Internal Pivot Host Identification  
   4.25 Flag 24 – First Suspicious Logon Event  
   4.26 Flag 25 – Source IP of Initial Logon  
   4.27 Flag 26 – Compromised Account Identification  
   4.28 Flag 27 – Attacker Geolocation  
   4.29 Flag 28 – First Process Executed Post-Logon  
   4.30 Flag 29 – First File Accessed by Attacker  
   4.31 Flag 30 – Post-Reconnaissance Activity  
   4.32 Flag 31 – Subsequent Account Access  
```
6. Visual Attack Timeline

```kql 
   5.1 Mermaid Attack Flow Diagram  
```

7. MITRE ATT&CK Mapping

```kql
   6.1 Initial Access  
   6.2 Execution  
   6.3 Persistence  
   6.4 Privilege Escalation  
   6.5 Defense Evasion  
   6.6 Command and Control  
```
8. Analyst Reasoning & Logical Flow  

9. Detection Gaps & Defensive Opportunities  

10. Conclusion & Incident Assessment  
```kql
11. Appendix  
   10.1 Full KQL Queries  
   10.2 Indicators of Compromise (IOCs)  
   10.3 Reference Notes  
```
-----

## Findings
## Investigation Walkthrough - Flag by Flag - Analyst Explanation

This section documents the **analyst reasoning and investigative purpose behind each flag**. Each flag represents a discrete hypothesis test used to validate attacker behavior, reconstruct the intrusion timeline, and distinguish malicious activity from legitimate operational noise.

---

### Flag 0 — Identify Affected Device and Timeframe

**Purpose:**  
Establish the scope of investigation by identifying which endpoint(s) were active during the suspected compromise window.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-2))
| project TimeGenerated, DeviceName, FileName
| order by TimeGenerated desc
```
<img width="783" height="428" alt="Screenshot 2026-02-10 at 11 32 50" src="https://github.com/user-attachments/assets/b0c383ca-d6cf-465c-94cf-ceb11169b6a8" />

**Result:**  
CH-OPS-WKS02 identified as the sole affected endpoint.

**Analyst Reasoning:**  
Before attributing intent or analyzing behavior, it is critical to anchor the investigation to a specific device and timeframe. By enumerating file activity across mid-November through early December, the analyst confirmed that anomalous behavior was localized to **CH-OPS-WKS02**, eliminating the possibility of a broader automation rollout or fleet-wide maintenance activity.

---

### Flag 1 — Unique Maintenance Script Identification

**Purpose:**  
Determine whether any scripts executed on the host deviated from standard CorpHealth tooling.
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where FileName endswith ".ps1" or FileName endswith ".bat" or FileName endswith ".cmd"
| where DeviceName has "CH-OPS-WKS02"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="1228" height="464" alt="Screenshot 2026-02-11 at 10 41 42" src="https://github.com/user-attachments/assets/80466608-a96a-46a2-be4f-648f11f1b554" />

**Result:**  
`MaintenanceRunner_Distributed.ps1`

**Analyst Reasoning:**  
CorpHealth scripts are typically standardized and deployed uniformly. Identifying a **single PowerShell script unique to CH-OPS-WKS02** suggested host-specific execution and raised suspicion that the script may have been introduced or modified locally rather than deployed through approved channels.

---

### Flag 2 — First Outbound Network Communication

**Purpose:**  
Identify the moment local script execution transitioned into off-host communication.
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where DeviceName has "CH-OPS-WKS02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated asc

```
<img width="1124" height="464" alt="Screenshot 2026-02-11 at 11 41 40" src="https://github.com/user-attachments/assets/d807994c-9fee-4b45-a21f-694d61b33071" />

**Result:**  
`2025-11-23T03:46:08.400686Z`

**Analyst Reasoning:**  
Outbound network activity marks a critical escalation point. By correlating the maintenance script’s command line with network telemetry, the analyst identified the **first beacon timestamp**, confirming that the script was not operating purely locally and had external awareness or control logic.

---

### Flag 3 — Beacon Destination Identification

**Purpose:**  
Determine the initial external endpoint targeted by the script.

**Result:**  
`127.0.0.1:8080`

**Analyst Reasoning:**  
The destination IP and port provide insight into attacker intent. The use of a **non-standard local port (8080)** immediately ruled out approved enterprise services and suggested staging, testing, or proxy behavior rather than legitimate diagnostics.

---

### Flag 4 — Successful Beacon Confirmation

**Purpose:**  
Validate whether outbound communication attempts succeeded.

<img width="1066" height="348" alt="Screenshot 2026-02-11 at 11 58 35" src="https://github.com/user-attachments/assets/1f6e71fa-a479-4148-9ab4-4e7c00846b18" />

**Result:**  
`2025-11-30T01:03:17.698Z`

**Analyst Reasoning:**  
Failed connection attempts can indicate misconfiguration or testing, while successful connections confirm reachability. Identifying a successful beacon validated that the script achieved its communication objective and was not simply misfiring.

---

### Flag 5 — Primary Staging Artifact Creation

**Purpose:**  
Identify the first attacker-created file written to disk.
```kql
DeviceFileEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where ActionType == "FileCreated"
| where FolderPath contains "Diagnostics" and FolderPath contains "CorpHealth" 
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="1262" height="360" alt="Screenshot 2026-02-11 at 13 05 01" src="https://github.com/user-attachments/assets/b9d7fd94-2fa4-4929-a806-acc5f7260aab" />


**Result:**  
`C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`

**Analyst Reasoning:**  
File creation immediately following beaconing often indicates **data staging or tool preparation**. The inventory CSV appearing under CorpHealth diagnostics paths suggested the attacker was leveraging trusted directories to blend malicious artifacts with legitimate operational output.

---

### Flag 6 — Hash Identification of Primary Artifact

**Purpose:**  
Capture the cryptographic fingerprint of the staged file.


**Result:**  
`7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`

**Analyst Reasoning:**  
Hashing enables artifact tracking, comparison, and potential threat intelligence correlation. This step also allows analysts to identify modified or duplicate versions of the same file later in the intrusion chain.

---

### Flag 7 — Secondary / Working Copy Artifact

**Purpose:**  
Identify alternate or temporary versions of the staged data.
```kql
DeviceFileEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-27))
//| where ActionType == "FileCreated"
//| where FileSize != 'Empty'
| where FileName startswith "inventory"
| project TimeGenerated, FileName, FileSize, FolderPath, SHA256
| order by TimeGenerated asc

```
<img width="1262" height="192" alt="Screenshot 2026-02-11 at 13 35 40" src="https://github.com/user-attachments/assets/5d1e57f8-69d9-4139-8ac6-7ae503a768d1" />

**Result:**  
`C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`

**Analyst Reasoning:**  
Attackers often duplicate or modify files during staging. The presence of a similarly named inventory file in a **user temp directory with a different hash** suggested manipulation, testing, or preparation for exfiltration rather than routine diagnostics.

---

### Flag 8 — Suspicious Registry Key Activity

**Purpose:**  
Detect registry modifications associated with credential or privilege reconnaissance.

```kql
DeviceRegistryEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| where InitiatingProcessFileName contains "powershell.exe" or InitiatingProcessFileName contains "pwsh"
| project TimeGenerated, InitiatingProcessFileName, RegistryKey
| order by TimeGenerated asc

```
<img width="1262" height="265" alt="Screenshot 2026-02-13 at 11 05 24" src="https://github.com/user-attachments/assets/f67b9c1f-5909-425e-8a1e-b2ffc13ab2a5" />

**Result:**  
`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`

**Analyst Reasoning:**  
The registry key touched during this phase aligns with event logging services and indicates the attacker was exploring system telemetry pathways — a common precursor to **credential harvesting or privilege manipulation**.

---

### Flag 9 — Unauthorized Scheduled Task Creation

**Purpose:**  
Identify persistence mechanisms introduced by the attacker.
```kql
DeviceRegistryEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| where RegistryKey has_any ('Schedule', 'TaskCache', 'Tree', 'GoogleUserPEH')
| project TimeGenerated, InitiatingProcessFileName, RegistryKey, ActionType
| order by TimeGenerated asc

```
<img width="1501" height="442" alt="Screenshot 2026-02-13 at 11 06 59" src="https://github.com/user-attachments/assets/875fcc04-0198-4f7c-ab49-151f1b0632dd" />

**Result:**  
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64`

**Analyst Reasoning:**  
Scheduled tasks are a reliable persistence technique. The creation of a **non-standard CorpHealth task** confirmed that the attacker intended to maintain execution capability beyond the initial session.

---

### Flag 10 — Registry Run Key Persistence

**Purpose:**  
Identify ephemeral startup persistence behavior.
```kql
DeviceRegistryEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet" or ActionType == "RegistryKeyDeleted"
| where RegistryKey has_any ('run')
| project TimeGenerated, InitiatingProcessFileName, RegistryKey, RegistryValueName
| order by TimeGenerated asc

```
<img width="1212" height="152" alt="Screenshot 2026-02-13 at 11 25 57" src="https://github.com/user-attachments/assets/1bb1db13-5731-4cc4-8aa7-93e5b6dba954" />

**Result:**  
`MaintenanceRunner`

**Analyst Reasoning:**  
The creation and rapid deletion of a Run key value indicates **single-use persistence**, often employed to survive a reboot while minimizing forensic artifacts. This behavior is strongly indicative of deliberate attacker tradecraft.

---

### Flag 11 — Privilege Escalation Event Timestamp

**Purpose:**  
Identify the exact moment privilege escalation was attempted.

```kql
DeviceEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-10))
| where AdditionalFields has "ConfigAdjust"
| project TimeGenerated, ActionType, AdditionalFields
| order by TimeGenerated desc

```
<img width="1001" height="411" alt="Screenshot 2026-02-13 at 11 52 29" src="https://github.com/user-attachments/assets/3dc61e48-9e1d-43d7-acda-ef2455460245" />

**Result:**  
`2025-11-23T03:47:21.8529749Z`

**Analyst Reasoning:**  
The `ConfigAdjust` event marks the transition from reconnaissance to privilege abuse. Timestamping this event anchors later actions—such as tool download and execution—to elevated privileges.

---

### Flag 12 — Antivirus Exclusion Attempt

**Purpose:**  
Determine whether the attacker attempted to weaken endpoint defenses.
```kql
DeviceProcessEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-12-8))
| where ProcessCommandLine contains "ExclusionPath"
| project TimeGenerated, ProcessCommandLine, InitiatingProcessAccountName
| order by TimeGenerated


```
<img width="1430" height="347" alt="Screenshot 2026-02-13 at 12 44 45" src="https://github.com/user-attachments/assets/47d942e1-b204-4eb5-83d6-d9fde798d2d3" />

**Result:**  
`C:\ProgramData\Corp\Ops\staging -Force > ".cli"`

**Analyst Reasoning:**  
Attempting to add an exclusion path to Windows Defender indicates intent to **shield malicious files from scanning**. Even though the attempt failed, the action itself confirms malicious intent rather than misconfigured automation.

---

### Flag 13 — Encoded PowerShell Execution

**Purpose:**  
Identify obfuscated command execution.
```kql
DeviceProcessEvents 
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-8))
| where ProcessCommandLine contains "-EncodedCommand"
| where AccountName != "system"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)


```
<img width="1466" height="356" alt="Screenshot 2026-02-13 at 16 33 23" src="https://github.com/user-attachments/assets/07cbd272-e0a3-4451-8a95-29a806b6b02d" />

**Decoded Result:**  
`Write-Output 'token-6D5E4EE08227'`

**Analyst Reasoning:**  
Encoded commands are rarely used in legitimate administration. Decoding the payload revealed a token string, confirming deliberate obfuscation and signaling attacker-controlled execution logic.

---

### Flag 14 — Token Privilege Modification

**Purpose:**  
Identify which process altered security token privileges.
```kql
DeviceEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where AdditionalFields has_any ('tokenChangeDescription', 'Privileges were added')
| where InitiatingProcessFileName has ('powershell.exe')
//| where InitiatingProcessAccountSid has "S-1-5-21-1605642021-30596605-784192815-1000"
| project TimeGenerated, FileName, InitiatingProcessId, AdditionalFields, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by TimeGenerated asc


```
<img width="1501" height="442" alt="Screenshot 2026-02-16 at 14 56 48" src="https://github.com/user-attachments/assets/ba8bf3ba-172c-4812-b579-66c97bfdc3a7" />

**Result:**  
InitiatingProcessId: `4888`

**Analyst Reasoning:**  
Token modification is a strong indicator of privilege escalation or impersonation. Identifying the initiating process ID allowed the analyst to tie this behavior directly to the attacker’s PowerShell execution chain.

---

### Flag 15 — Token Ownership Identification

**Purpose:**  
Determine whose privileges were modified.
```kql
DeviceEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where AdditionalFields has_any ('tokenChangeDescription', 'Privileges were added')
| where InitiatingProcessFileName has ('powershell.exe')
//| where InitiatingProcessAccountSid has "S-1-5-21-1605642021-30596605-784192815-1000"
| project TimeGenerated, FileName, InitiatingProcessId, AdditionalFields, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountSid
| order by TimeGenerated asc


```
<img width="1353" height="442" alt="Screenshot 2026-02-16 at 15 05 21" src="https://github.com/user-attachments/assets/34f349d7-f156-4af9-82e7-7577402d7e99" />

**Result:**  
`S-1-5-21-1605642021-30596605-784192815-1000`

**Analyst Reasoning:**  
Knowing the SID tied to the modified token clarifies risk. Modification of a **local administrator token** significantly elevates the severity of the incident and confirms successful privilege abuse.

---

### Flag 16 — Ingress Tool Transfer

**Purpose:**  
Identify the executable introduced post-escalation.
```kql
DeviceFileEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where FileName endswith ".exe"
| where InitiatingProcessFileName has ('powershell.exe')

```
<img width="1602" height="297" alt="Screenshot 2026-02-16 at 15 28 00" src="https://github.com/user-attachments/assets/5252a3bc-744e-478e-81a8-e71755a2051f" />

**Result:**  
`revshell.exe`

**Analyst Reasoning:**  
The appearance of a new unsigned executable immediately after external communication indicates tool delivery. This confirms the attacker moved from staging to **active tooling deployment**.

---

### Flag 17 — External Download Source Identification

**Purpose:**  
Identify where the payload originated.
```kql
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
//| where InitiatingProcessFileName endswith ".exe"
| where InitiatingProcessFileName has ('powershell.exe')


```
<img width="1127" height="350" alt="Screenshot 2026-02-16 at 15 52 26" src="https://github.com/user-attachments/assets/6858f58d-fbf5-4a09-bf7c-932daf06fe35" />

**Result:**  
`unresuscitating-donnette-smothery.ngrok-free.dev`

**Analyst Reasoning:**  
The use of an **ngrok dynamic tunnel domain** aligns with attacker tradecraft for temporary, disposable infrastructure and strongly supports a malicious classification.

---

### Flag 18 — Execution of Staged Binary

**Purpose:**  
Confirm execution of the downloaded tool.
```kql
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
//| where InitiatingProcessFileName endswith ".exe"
| where InitiatingProcessFileName has ('powershell.exe')
| where InitiatingProcessAccountDomain != "nt authority"
| where RemotePort == 443


```
<img width="740" height="468" alt="Screenshot 2026-02-16 at 16 14 35" src="https://github.com/user-attachments/assets/83290fc1-d43b-4d43-ad8a-09daca64393c" />

**Result:**  
`explorer.exe`

**Analyst Reasoning:**  
Execution marks the shift from preparation to active control. The binary being launched via **explorer.exe** suggests user-context execution and interactive control rather than scheduled automation.

---

### Flag 19 — External IP Contacted by Executable

**Purpose:**  
Identify the command-and-control endpoint.
```kql
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where RemotePort == '11746'
| where ActionType == "ConnectionFailed"


```
<img width="788" height="523" alt="Screenshot 2026-02-16 at 16 34 35" src="https://github.com/user-attachments/assets/0152f9b2-4aeb-43c8-bcf5-85408b8159b7" />

**Result:**  
`13.228.171.119`

**Analyst Reasoning:**  
Repeated failed outbound connections to a high, non-standard port indicate attempted C2 establishment rather than benign traffic.

---

### Flag 20 — Startup Folder Persistence

**Purpose:**  
Identify a secondary persistence mechanism.
```kql
DeviceFileEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where FileName endswith ".exe"
| where InitiatingProcessAccountDomain != "nt authority"


```
<img width="1231" height="488" alt="Screenshot 2026-02-16 at 16 56 18" src="https://github.com/user-attachments/assets/5b405423-6cc4-4d80-b2f6-1a038843b412" />

**Result:**  
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

**Analyst Reasoning:**  
Placing the executable in the Startup folder ensures execution at every logon. This confirms long-term access intent even if scheduled tasks or registry persistence fail.

---

### Flag 21 — Remote Session Source Device

**Purpose:**  
Identify the attacker’s remote session identifier.
```kql
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where InitiatingProcessAccountDomain != "nt authority"

```
<img width="1231" height="488" alt="Screenshot 2026-02-18 at 12 09 54" src="https://github.com/user-attachments/assets/dedf7b28-7662-476c-a4d4-e53b2b4e7a0a" />

**Result:**  
`对手`

**Analyst Reasoning:**  
The unusual device name provides correlation context across sessions and supports attribution of multiple events to the same remote operator.

---

### Flag 22 — Remote Session IP Address

**Purpose:**  
Identify the IP associated with the remote session.

**Result:**  
`100.64.100.6`

**Analyst Reasoning:**  
This IP helps distinguish between internal pivoting, VPN usage, or external access paths.

---

### Flag 23 — Internal Pivot Host Identification

**Purpose:**  
Identify lateral movement or relay infrastructure.

**Result:**  
`10.168.0.6`

**Analyst Reasoning:**  
The presence of a non-100.64.x.x internal IP suggests pivoting or use of internal infrastructure rather than direct external access.

---

### Flag 24 — First Suspicious Logon Timestamp

**Purpose:**  
Identify the true beginning of attacker presence.
```kql
DeviceLogonEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-09))
| where InitiatingProcessAccountDomain != "nt authority"
| where AccountDomain has "CH-OPS-WKS02"
| project TimeGenerated, AccountDomain, AccountName, ActionType, Timestamp, RemoteIP, IsInitiatingProcessRemoteSession
| order by TimeGenerated asc

```

**Result:**  
`2025-11-23T03:08:31.1849379Z`

**Analyst Reasoning:**  
This timestamp anchors the entire intrusion timeline and distinguishes initial access from follow-on activity.

---

### Flag 25 — Source IP of Initial Access

**Purpose:**  
Identify where the attacker first logged in from.

**Result:**  
`104.164.168.17`

**Analyst Reasoning:**  
The initial source IP provides context for threat intelligence enrichment and helps determine whether access was internal, external, or via a relay.

---

### Flag 26 — Account Used for Initial Access

**Purpose:**  
Identify compromised credentials.

<img width="1269" height="494" alt="Screenshot 2026-02-18 at 12 48 44" src="https://github.com/user-attachments/assets/4b1defb8-00b7-40df-9de4-e1146fefc1b2" />

**Result:**  
`chadmin`

**Analyst Reasoning:**  
Knowing which account was used confirms credential compromise and guides remediation actions such as password resets and access reviews.

---

### Flag 27 — Attacker Geographic Region

**Purpose:**  
Add geopolitical and intelligence context.
```kql
DeviceLogonEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-09))
| where RemoteIPType == "Public"
| where AccountName == "chadmin"
| extend Geo = geo_info_from_ip_address(RemoteIP)
| project TimeGenerated, RemoteIP, Geo, AccountDomain
| order by TimeGenerated asc


```
<img width="1269" height="494" alt="Screenshot 2026-02-18 at 13 19 14" src="https://github.com/user-attachments/assets/b1eb92d0-49a5-450b-b7e5-00ba31fb7bf5" />

**Result:**  
Vietnam

**Analyst Reasoning:**  
Geolocation enrichment revealed consistent access from **Vietnam**, supporting attribution context and reinforcing that the activity was not local administrative work.

---

### Flag 28 — First Process Executed Post-Logon

**Purpose:**  
Understand attacker priorities after access.
```kql
DeviceProcessEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-09))
| where InitiatingProcessAccountDomain != "nt authority"
| where AccountName == "chadmin"
```
<img width="1269" height="494" alt="Screenshot 2026-02-18 at 13 29 47" src="https://github.com/user-attachments/assets/56b2e719-6799-4f08-9b78-7875a440ab48" />

**Result:**  
`explorer.exe`

**Analyst Reasoning:**  
Launching `explorer.exe` indicates environment familiarization and interactive access rather than automated execution.

---

### Flag 29 — First File Accessed

**Purpose:**  
Identify attacker intent.
```kql
DeviceProcessEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-09))
| where InitiatingProcessAccountName == "chadmin"
| where FileName in ("notepad.exe", "explorer.exe", "mmc.exe", "eventvwr.msc", "services.msc", "regedit.exe")
//| where ProcessCommandLine has "\\"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="883" height="494" alt="Screenshot 2026-02-18 at 14 39 42" src="https://github.com/user-attachments/assets/94351258-674e-4b43-a086-aa47932ac407" />

**Result:**  
`user-pass.txt`

**Analyst Reasoning:**  
Opening a file named `user-pass.txt` strongly suggests **credential harvesting** as the attacker’s immediate objective.

---

### Flag 30 — Post-Credential Action

**Purpose:**  
Determine next operational step.

**Result:**  
`ipconfig`

**Analyst Reasoning:**  
Running `ipconfig` confirms reconnaissance and environment validation prior to further movement or tool execution.

---

### Flag 31 — Next Account Accessed

**Purpose:**  
Identify lateral or privilege movement.
```kql
DeviceLogonEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-09))
| where RemoteIPType == "Public"
| project TimeGenerated, RemoteIP, AccountDomain, AccountName
| order by TimeGenerated asc

```
<img width="877" height="227" alt="Screenshot 2026-02-18 at 14 59 47" src="https://github.com/user-attachments/assets/fec288c9-e739-4d5f-a8cb-de50009006c8" />

**Result:**  
`ops.maintenance`

**Analyst Reasoning:**  
Accessing the `ops.maintenance` account indicates the attacker began testing or leveraging additional credentials after initial enumeration.

----

## End of Flag Explanations

## MITRE ATT&CK Mapping

*This section maps confirmed attacker behaviors observed during the investigation to the MITRE ATT&CK framework, demonstrating structured adversary tradecraft across multiple tactics.*

**Initial Access**
| Technique ID  | Technique Name       | Evidence                                           |
| ------------- | -------------------- | -------------------------------------------------- |
| **T1078**     | Valid Accounts       | Interactive logon using compromised account `chad` |
| **T1021.001** | Remote Services: RDP | Remote authentication from external IPs            |
----
**Execution**
| Technique ID  | Technique Name        | Evidence                                            |
| ------------- | --------------------- | --------------------------------------------------- |
| **T1059.001** | PowerShell            | Encoded PowerShell execution, registry manipulation |
| **T1059.003** | Windows Command Shell | `ipconfig` executed post-logon                      |
| **T1106**     | Native API            | Execution via trusted binaries (`explorer.exe`)     |
----
**Persistence**
| Technique ID  | Technique Name                     | Evidence                                         |
| ------------- | ---------------------------------- | ------------------------------------------------ |
| **T1547.001** | Registry Run Keys / Startup Folder | Registry Run key + Startup folder `revshell.exe` |
| **T1053.005** | Scheduled Task                     | Unauthorized scheduled task `CorpHealth_A65E64`  |

----

**Privilege Escalation**
| Technique ID | Technique Name                        | Evidence                            |
| ------------ | ------------------------------------- | ----------------------------------- |
| **T1068**    | Exploitation for Privilege Escalation | Token manipulation attempts         |
| **T1134**    | Access Token Manipulation             | Token inspection / SID modification |

----

**Defense Evasion**
| Technique ID  | Technique Name                            | Evidence                                 |
| ------------- | ----------------------------------------- | ---------------------------------------- |
| **T1562.001** | Disable or Modify Security Tools          | Windows Defender exclusion attempt       |
| **T1027**     | Obfuscated / Encoded Files or Information | Base64 PowerShell payload                |
| **T1036**     | Masquerading                              | Use of CorpHealth naming and directories |

----

**Credential Access**
| Technique ID  | Technique Name        | Evidence                                             |
| ------------- | --------------------- | ---------------------------------------------------- |
| **T1552.001** | Credentials in Files  | First file accessed: `user-pass.txt`                 |
| **T1003**     | OS Credential Dumping | Registry inspection resembling credential harvesting |

----

**Discovery**
| Technique ID | Technique Name                  | Evidence                          |
| ------------ | ------------------------------- | --------------------------------- |
| **T1082**    | System Information Discovery    | Inventory CSV creation            |
| **T1016**    | Network Configuration Discovery | `ipconfig` execution              |
| **T1046**    | Network Service Discovery       | Host/network enumeration behavior |

----

**Collection**
| Technique ID | Technique Name         | Evidence                          |
| ------------ | ---------------------- | --------------------------------- |
| **T1005**    | Data from Local System | Staged diagnostic inventory files |
| **T1119**    | Automated Collection   | Script-driven data export         |

----

**Command and Control**
| Technique ID  | Technique Name    | Evidence                               |
| ------------- | ----------------- | -------------------------------------- |
| **T1071.001** | Web Protocols     | HTTPS traffic initiated via `curl.exe` |
| **T1573**     | Encrypted Channel | Encrypted ngrok tunnel                 |
| **T1090**     | Proxy             | Dynamic tunnel usage                   |

----

**Exfiltration (Preparation)**
| Technique ID  | Technique Name                   | Evidence                   |
| ------------- | -------------------------------- | -------------------------- |
| **T1020**     | Automated Exfiltration (Staging) | Multiple staging locations |
| **T1567.002** | Exfiltration Over Web Service    | Prepared but not confirmed |

----




## Timeline
    title CorpHealth Intrusion Timeline (CH-OPS-WKS02)

    2025-11-23 03:08:31 : External attacker logs in using compromised account (chad)
    2025-11-23 03:09:14 : GUI session established (explorer.exe)
    2025-11-23 03:09:22 : First file accessed: user-pass.txt
    2025-11-23 03:10:01 : Network discovery executed (ipconfig)

    2025-11-23 03:46:08 : PowerShell maintenance script executed
    2025-11-23 03:47:21 : Privilege escalation attempt detected

    2025-11-24 01:12:09 : Primary inventory CSV staged (CorpHealth Diagnostics)
    2025-11-24 01:13:41 : Secondary working copy staged (Temp directory)

    2025-11-25 00:42:18 : Suspicious registry key created (Credential harvesting)
    2025-11-25 00:43:56 : Scheduled task persistence added

    2025-11-26 02:11:08 : Windows Defender exclusion attempted
    2025-11-27 04:18:33 : Reverse shell downloaded via ngrok tunnel

    2025-11-27 04:19:10 : revshell.exe executed via explorer.exe
    2025-11-27 04:20:01 : Startup folder persistence established
------


## Conclusion

This investigation determined that the activity on **CH-OPS-WKS02** was **malicious**, not legitimate CorpHealth operations. The attacker used valid credentials (`chadmin`) to gain access, performed early reconnaissance and credential discovery, escalated privileges through token manipulation, and established persistence using registry keys, scheduled tasks, and the Startup folder.

Following escalation, the attacker staged and executed an unsigned binary (`revshell.exe`) delivered via an external **ngrok** tunnel and attempted outbound command-and-control communication. Encoded PowerShell usage, short-lived persistence, and selective cleanup indicate deliberate evasion rather than automation errors.

Overall, the evidence confirms a **hands-on intrusion** abusing trusted automation infrastructure, emphasizing the risk of over-privileged service accounts and the need for tighter monitoring of operational tooling and credential use.


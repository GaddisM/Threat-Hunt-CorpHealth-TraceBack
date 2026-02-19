# CorpHealth : TraceBack
**Threat Hunting Investigation Report**

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

---

## Executive Summary

CorpHealth is an internally developed automation framework designed to perform endpoint diagnostics and maintenance using a privileged service account. In mid-November, anomalous activity surfaced on a single operational workstation. While early indicators resembled legitimate maintenance behavior, deviations in execution patterns, outbound connectivity, registry manipulation, privilege escalation, and external tooling delivery confirmed **unauthorized use of privileged access**.

The investigation reconstructs a full intrusion chain beginning with credential-based logon, followed by reconnaissance, privilege escalation, staging, payload delivery via an external tunnel, command-and-control attempts, and persistence establishment.

----

## Investigation Methodology

This investigation followed a **hypothesis-driven threat hunting model**:

1. **Scope Definition** – Identify affected assets and timeframe  
2. **Baseline Validation** – Compare observed activity against known CorpHealth behavior  
3. **Behavioral Deviation Analysis** – Identify anomalies across process, file, registry, and network telemetry  
4. **Timeline Reconstruction** – Correlate events chronologically  
5. **Intent Determination** – Assess attacker objectives and tradecraft  
6. **Attribution Context** – Enrich with session metadata and geolocation  
7. **Closure & Synthesis** – Reconstruct full attack chain  



Each flag represents a validated hypothesis checkpoint.

---



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

**Result:**  
`CorpHealth_A65E64`

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
**Result:**  
`C:\ProgramData\Corp\Ops\staging`

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

| Tactic               | Technique             | ID        |
| -------------------- | --------------------- | --------- |
| Initial Access       | Valid Accounts        | T1078     |
| Execution            | PowerShell            | T1059.001 |
| Defense Evasion      | AV Exclusion          | T1562.001 |
| Credential Access    | Credential Harvesting | T1003     |
| Privilege Escalation | Token Manipulation    | T1134     |
| Persistence          | Run Keys / Startup    | T1547     |
| Persistence          | Scheduled Task        | T1053     |
| Command & Control    | Proxy / Tunnel        | T1090     |
| Exfiltration Prep    | Data Staging          | T1074     |

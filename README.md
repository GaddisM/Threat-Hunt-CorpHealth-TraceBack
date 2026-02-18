# CorpHealth Privileged Automation Review  
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

---

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

## Flag 0 — Identify Affected Device and Timeframe

**Objective:** Establish scope.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-2))
| project TimeGenerated, DeviceName, FileName
| order by TimeGenerated desc







# CorpHealth Privileged Automation Review  
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

---

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

## Flag 0 — Identify Affected Device and Timeframe

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-2))
| project TimeGenerated, DeviceName, FileName
| order by TimeGenerated desc
```

**Result:**  
CH-OPS-WKS02 identified as the sole affected endpoint.

---

## Flag 1 — Unique Maintenance Script

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

**Explanation:**  
Script was unique to the host, deviating from standard CorpHealth deployments.

---

## Flag 2 — First Outbound Communication

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

---

## Flag 3 — Beacon Destination

**Result:**  
`127.0.0.1:8080`

**Explanation:**  
Non-standard port indicates staging or testing behavior, not diagnostics.

---

## Flag 4 — Successful Beacon

**Result:**  
`2025-11-30T01:03:17.698Z`

---

## Flag 5 — Primary Staging Artifact

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

---

## Flag 6 — SHA-256 of Primary Artifact

**Result:**  
`7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`

---

## Flag 7 — Secondary / Working Copy Artifact

```kql
DeviceFileEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-27))
| where FileName startswith "inventory"
| project TimeGenerated, FileName, FileSize, FolderPath, SHA256
| order by TimeGenerated asc
```

**Result:**  
`C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`

---

## Flag 8 — Suspicious Registry Activity

```kql
DeviceRegistryEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE"
| where InitiatingProcessFileName contains "powershell.exe"
| project TimeGenerated, InitiatingProcessFileName, RegistryKey
| order by TimeGenerated asc
```

**Result:**  
`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`

---

## Flag 9 — Scheduled Task Persistence

```kql
DeviceRegistryEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where RegistryKey has_any ('Schedule','TaskCache','Tree')
| project TimeGenerated, RegistryKey
```

**Result:**  
`CorpHealth_A65E64`

---

## Flag 10 — Run Key Persistence

```kql
DeviceRegistryEvents
| where DeviceName has "CH-OPS-WKS02"
| where RegistryKey has_any ('run')
| project TimeGenerated, RegistryKey, RegistryValueName
| order by TimeGenerated asc
```

**Result:**  
`MaintenanceRunner`

---

## Flag 11 — Privilege Escalation Timestamp

```kql
DeviceEvents
| where AdditionalFields has "ConfigAdjust"
| project TimeGenerated
```

**Result:**  
`2025-11-23T03:47:21.8529749Z`

---

## Flag 12 — AV Exclusion Attempt

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "ExclusionPath"
| project TimeGenerated, ProcessCommandLine
```

**Result:**  
`C:\ProgramData\Corp\Ops\staging`

---

## Flag 13 — Encoded PowerShell Execution

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-EncodedCommand"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
```

**Decoded Result:**  
`Write-Output 'token-6D5E4EE08227'`

---

## Flag 14 — Token Privilege Modification

**Result:**  
InitiatingProcessId: `4888`

---

## Flag 15 — Token Owner SID

**Result:**  
`S-1-5-21-1605642021-30596605-784192815-1000`

---

## Flag 16 — Tool Ingress

**Result:**  
`revshell.exe`

---

## Flag 17 — External Download Source

```kql
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where InitiatingProcessFileName has ('powershell.exe')
| where InitiatingProcessAccountDomain != "nt authority"
| where RemotePort == 443
```

**Result:**  
`unresuscitating-donnette-smothery.ngrok-free.dev`

---

## Flag 18 — Executed By

**Result:**  
`explorer.exe`

---

## Flag 19 — External IP Contacted

```kql
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-22) .. datetime(2025-12-03))
| where RemotePort == '11746'
| where ActionType == "ConnectionFailed"
```

**Result:**  
`13.228.171.119`

---

## Flag 20 — Startup Persistence Path

**Result:**  
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

---

## Flag 21 — Remote Session Device

**Result:**  
`对手`

---

## Flag 22 — Remote Session IP

**Result:**  
`100.64.100.6`

---

## Flag 23 — Internal Pivot Host

**Result:**  
`10.168.0.6`

---

## Flag 24 — First Suspicious Logon

```kql
DeviceLogonEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-09))
| where InitiatingProcessAccountDomain != "nt authority"
| project TimeGenerated, AccountDomain, AccountName, ActionType, Timestamp, RemoteIP, IsInitiatingProcessRemoteSession
| order by TimeGenerated asc
```

**Result:**  
`2025-11-23T03:08:31.1849379Z`

---

## Flag 25 — Initial Access IP

**Result:**  
`104.164.168.17`

---

## Flag 26 — Compromised Account

**Result:**  
`chadmin`

---

## Flag 27 — Attacker Geolocation

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

---

## Flag 28 — First Process Post-Logon

**Result:**  
`explorer.exe`

---

## Flag 29 — First File Accessed

```kql
DeviceProcessEvents
| where DeviceName has "CH-OPS-WKS02"
| where TimeGenerated between (datetime(2025-11-21) .. datetime(2025-12-09))
| where InitiatingProcessAccountName == "chadmin"
| where FileName in ("notepad.exe", "explorer.exe", "mmc.exe", "eventvwr.msc", "services.msc", "regedit.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Result:**  
`user-pass.txt`

---

## Flag 30 — Next Action

**Result:**  
`ipconfig`

---

## Flag 31 — Next Account Accessed

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


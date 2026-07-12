# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Suspicious PowerShell Execution from Office Applications |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 32a34030-25d7-43fe-b031-9be1265d9956 |
| MITRE Technique | Command and Scripting Interpreter: PowerShell |
| MITRE ID | T1059.001 |
| MITRE Tactic | Execution |
| Severity | High |
| Detection Confidence | High |
| Detection Maturity | Production Ready (90) |
| Quality Score | 90 (PASS) |
| Deployment Platforms | Windows Workstations, Windows Servers |
| Required Logs | Microsoft-Windows-Sysmon/Operational, Security Event Log |
| Generated | 2026-07-12T05:34:06.212Z |
| Updated | 2026-07-12T05:34:06.212Z |

## Executive Summary

This detection identifies suspicious PowerShell execution originating from Microsoft Office applications. This behavior is a primary indicator of malicious macro execution, often used to download and execute secondary payloads, establish persistence, or perform reconnaissance. Immediate investigation is recommended as this is a high-confidence indicator of compromise.

## Use Case

Detect suspicious PowerShell execution spawning from Microsoft Office applications

## MITRE ATT&CK

- **Tactic:** Execution
- **Technique:** Command and Scripting Interpreter: PowerShell
- **Technique ID:** T1059.001

## Detection Logic

Identify process creation events where the parent process is a known Microsoft Office application (winword.exe, excel.exe, powerpnt.exe, outlook.exe, mspub.exe, visio.exe) and the child process is powershell.exe or pwsh.exe.

### Detection Confidence

**High** — Spawning PowerShell from Office applications (Word, Excel, PowerPoint) is a classic indicator of macro-based malware delivery. While some legitimate administrative scripts may exist, they are extremely rare in modern enterprise environments and typically warrant immediate investigation.

### Detection Maturity

**Production Ready** (score 90) — High fidelity detection with minimal false positives in standard office environments.

## Sigma Rule

```yaml
title: PowerShell Spawning from Office Application
id: 5f8a9c2b-1234-4567-8901-abcdef123456
status: experimental
description: Detects PowerShell spawned by Microsoft Office applications.
author: Detection Engineering Team
date: 2023-10-27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mspub.exe'
      - '\visio.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  condition: selection
falsepositives:
  - Rare administrative scripts
level: high
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation/
```

## Splunk SPL

```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
ParentImage IN ("*\\winword.exe", "*\\excel.exe", "*\\powerpnt.exe", "*\\outlook.exe", "*\\mspub.exe", "*\\visio.exe")
Image IN ("*\\powershell.exe", "*\\pwsh.exe")
| stats count by _time, Computer, User, ParentImage, Image, CommandLine
| sort - _time
```

## Microsoft Sentinel KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe', 'visio.exe')
| where FileName in~ ('powershell.exe', 'pwsh.exe')
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

## Elastic Query

```json
{"query":{"bool":{"filter":[{"terms":{"process.parent.name.keyword":["winword.exe","excel.exe","powerpnt.exe","outlook.exe","mspub.exe","visio.exe"]}},{"terms":{"process.name.keyword":["powershell.exe","pwsh.exe"]}}]}}}
```

## Coverage

- **Required Logs:** Microsoft-Windows-Sysmon/Operational, Security Event Log
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Endpoint Process Creation
- **Deployment Platforms:** Windows Workstations, Windows Servers
- **Recommended Log Retention:** 90 days

### Coverage Summary

- **Telemetry Sources:** Endpoint Process Creation
- **Required Event IDs:** 4688
- **Required Sysmon Events:** 1
- **Recommended Log Sources:** Sysmon Event ID 1, Windows Event ID 4688
- **Windows Event IDs:** 4688
- **Sysmon Event IDs:** 1

## Threat Intelligence

- **Related Attack Groups:** APT28, FIN7, TA505
- **Known Malware:** Emotet, Qakbot, TrickBot, IcedID
- **Common Initial Access:** Spearphishing Attachment, Drive-by Compromise
- **Common Persistence:** Scheduled Task, Registry Run Keys

### False Positives

- Rare administrative scripts using Office automation (should be baselined)
- Legitimate software deployment tools using Office plugins (rare)

## Investigation Checklist

### Immediate Actions

- Identify the user and host involved.
- Determine the source of the Office document (email, download, etc.).
- Check for persistence mechanisms created by the script.

### Evidence Collection

- Capture the full command line of the PowerShell process.
- Extract the Office document that triggered the macro.
- Collect memory dumps if the process is still active.
- Review recent network connections from the host.

### Threat Hunting Queries

- index=endpoint (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe") Image="*\\powershell.exe" | stats count by Computer, User, CommandLine

### Next Investigation Steps

- Analyze the macro code if the document is available.
- Check for lateral movement attempts from the compromised host.
- Review EDR/AV alerts for the same host.

### Containment

- Isolate the affected host from the network.
- Terminate the suspicious PowerShell process tree.
- Disable the user account if credential compromise is suspected.

### Recovery

- Restore the host from a clean backup if necessary.
- Reset user credentials.
- Update security policies to block macros from untrusted sources.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 90
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Rule is well-structured and targets a high-risk behavior. Elastic query was updated to be more performant and accurate.

### Improvements Made

- Updated Elastic query to use .keyword fields for exact matching.
- Added pwsh.exe to Elastic query.
- Updated detection_logic to accurately reflect the query.

## Version History

**Version:** 1.1.0

- Initial version
- Updated Elastic query to use keyword fields for exact matching and added pwsh.exe support.
- Updated detection logic description to match actual implementation.

## References

- https://attack.mitre.org/techniques/T1059/001/
- https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation/

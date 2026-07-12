# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Suspicious PowerShell Execution from Office Application |
| Severity | High |
| Detection Confidence | High |
| Detection Maturity | Production Ready (90) |
| MITRE Technique | Command and Scripting Interpreter: PowerShell |
| MITRE ID | T1059.001 |
| Version | 1.1.0 |
| Quality Score | 95 (PASS) |
| Generated Time | 2026-07-12T04:15:54.236Z |

## Executive Summary

This detection identifies suspicious PowerShell execution originating from Microsoft Office applications. This behavior is a primary indicator of macro-based malware delivery, where an attacker uses malicious VBA macros to launch PowerShell to download or execute secondary payloads. This is a critical detection point for preventing initial access and lateral movement.

## Use Case

Detect suspicious PowerShell execution spawning from Microsoft Office applications

## MITRE ATT&CK

- **Tactic:** Execution
- **Technique:** Command and Scripting Interpreter: PowerShell
- **Technique ID:** T1059.001

## Detection Logic

Monitor process creation events where the parent process is a known Microsoft Office application (winword.exe, excel.exe, powerpnt.exe, outlook.exe, mspub.exe, visio.exe) and the child process is powershell.exe or pwsh.exe. Include command line arguments to identify obfuscated or encoded commands.

### Detection Confidence

**High** — The spawning of PowerShell from Office applications (winword.exe, excel.exe, powerpnt.exe) is a classic indicator of macro-based malware execution. While some legitimate administrative scripts exist, they are rare in standard office environments, making this a high-fidelity signal.

### Detection Maturity

**Production Ready** (score 90) — This detection targets a well-known and highly effective attack vector with minimal false positives in hardened environments.

## Sigma Rule

```yaml
title: PowerShell Spawning from Office Application
id: 5e3a8d21-9f2b-4c12-8a3d-9e4f1b2c3d4e
status: stable
description: Detects PowerShell being spawned by Microsoft Office applications, a common indicator of macro-based malware.
author: Detection Engineering
date: 2023-10-27
references:
  - https://attack.mitre.org/techniques/T1059/001/
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
  - Legitimate administrative scripts
level: high
```

## Splunk SPL

```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4688
| search ParentProcessName IN (\"*\\\\winword.exe\", \"*\\\\excel.exe\", \"*\\\\powerpnt.exe\", \"*\\\\outlook.exe\", \"*\\\\mspub.exe\", \"*\\\\visio.exe\")
| search process_name IN (\"powershell.exe\", \"pwsh.exe\")
| table _time, ComputerName, User, ParentProcessName, process_name, CommandLine
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
{
  "bool": {
    "must": [
      { "terms": { "process.parent.name": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "visio.exe"] } },
      { "terms": { "process.name": ["powershell.exe", "pwsh.exe"] } }
    ]
  }
}
```

## Coverage

- **Required Logs:** Sysmon Event ID 1, Windows Security Event ID 4688
- **Required Products:** Microsoft Defender for Endpoint, Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Endpoint Process Monitoring
- **Deployment Platforms:** Windows Workstations, Windows Servers
- **Recommended Log Retention:** 90 days

### Coverage Summary

- **Telemetry Sources:** Endpoint Process Creation
- **Required Event IDs:** 4688
- **Required Sysmon Events:** 1
- **Recommended Log Sources:** Sysmon Event ID 1, Security Event ID 4688
- **Windows Event IDs:** 4688
- **Sysmon Event IDs:** 1

## Threat Intelligence

- **Related Attack Groups:** APT28, FIN7, TA505
- **Known Malware:** Emotet, TrickBot, Qakbot, IcedID
- **Common Initial Access:** Spearphishing Attachment, Drive-by Compromise
- **Common Persistence:** Scheduled Task, Registry Run Keys

### False Positives

- Legitimate administrative scripts used by IT (rare)
- Third-party add-ins that utilize PowerShell for legitimate updates (should be baselined)

## Investigation Checklist

### Immediate Actions

- Identify the user and the specific Office document involved.
- Check for network connections initiated by the PowerShell process.
- Review recent file modifications by the user.

### Evidence Collection

- Capture the full command line of the PowerShell process.
- Extract the malicious Office document from the user's profile or temp folders.
- Collect memory dumps if the process is still active.

### Threat Hunting Queries

- index=endpoint (ParentImage=\"*\\\\winword.exe\" OR ParentImage=\"*\\\\excel.exe\") Image=\"*\\\\powershell.exe\" | stats count by User, CommandLine, ParentCommandLine

### Next Investigation Steps

- Analyze the macro code within the document.
- Check for secondary payloads downloaded by the script.
- Review logs for lateral movement attempts from the compromised host.

### Containment

- Isolate the affected host from the network.
- Terminate the suspicious PowerShell process tree.
- Disable the user account if credential compromise is suspected.

### Recovery

- Restore the host from a known good backup if necessary.
- Reset user credentials.
- Update endpoint security policies to block macros from untrusted sources.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 95
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

The detection is well-structured and covers the primary attack vector for Office-based PowerShell execution.

### Improvements Made

- Updated Sigma status to stable.
- Optimized Splunk query.

## Version History

**Version:** 1.1.0

- Initial version
- Updated Sigma rule status to 'stable' and added missing 'logsource' fields. Refined Splunk SPL to use process_name for better performance.

## References

- https://attack.mitre.org/techniques/T1059/001/
- https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation/

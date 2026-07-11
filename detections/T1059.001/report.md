# Detection Engineering Report

| Field | Value |
|-------|-------|
| Title | Suspicious PowerShell Execution from Office Applications |
| Severity | High |
| MITRE Technique | Command and Scripting Interpreter: PowerShell |
| MITRE ID | T1059.001 |
| Detection Confidence | High |
| Windows Event IDs | 4688 |
| Sysmon Events | 1 |

**Generated:** 2026-07-11T21:20:42.579Z

## Executive Summary

This detection identifies suspicious PowerShell execution originating from Microsoft Office applications. This behavior is a classic indicator of macro-based malware, where an attacker uses Office macros to launch PowerShell to download or execute secondary payloads. This is a critical stage in the initial access and execution phases of an attack.

## Use Case

Detect suspicious PowerShell execution spawning from Microsoft Office applications

## MITRE ATT&CK

- **Tactic:** Execution
- **Technique:** Command and Scripting Interpreter: PowerShell
- **Technique ID:** T1059.001

## Detection Confidence

**High** — The detection is highly reliable because Office applications spawning PowerShell is almost never a legitimate business process. The inclusion of command-line argument filtering reduces noise from benign but unusual activity.

## Detection Logic

The detection monitors process creation events (Sysmon Event ID 1 or Windows Event ID 4688) where the parent process is a known Microsoft Office application and the child process is powershell.exe or pwsh.exe. The query is intentionally broad on the process relationship to catch all instances, as this behavior is inherently suspicious. Command-line filtering is applied to highlight common obfuscation techniques used by attackers.

## Sigma Rule

```yaml
title: Office Application Spawning PowerShell
id: 5f3b4a21-8c9e-4f2a-b1d3-9e8f7a6b5c4d
status: experimental
description: Detects PowerShell execution spawned by Microsoft Office applications.
author: SOC Detection Engineering
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
index=windows (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe" OR ParentImage="*\\outlook.exe" OR ParentImage="*\\mspub.exe" OR ParentImage="*\\visio.exe") (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

## Microsoft Sentinel KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe', 'visio.exe')
| where FileName in~ ('powershell.exe', 'pwsh.exe')
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| sort by TimeGenerated desc
```

## Elastic Query DSL

```json
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "process.parent.name": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "visio.exe"] } },
        { "terms": { "process.name": ["powershell.exe", "pwsh.exe"] } }
      ]
    }
  }
}
```

## Windows Event IDs

- 4688

## Sysmon Event IDs

- 1

## False Positives

- Legitimate administrative scripts or automated reporting tools that utilize Office macros to trigger PowerShell tasks.
- Third-party plugins or add-ins that use PowerShell for legitimate integration tasks.

## Investigation Checklist

### Immediate Actions

- Identify the user and host involved.
- Determine if the PowerShell script successfully executed external network connections.
- Check for other suspicious processes spawned by the same Office document.

### Evidence Collection

- Capture the full command line of the PowerShell process.
- Retrieve the Office document that triggered the macro.
- Collect memory dumps from the affected host if possible.
- Extract any downloaded files or network connections initiated by the PowerShell script.

### Threat Hunting Queries

- Search for other processes spawned by the same Office document.
- Search for network connections initiated by the PowerShell process.
- Search for file modifications in temporary directories (e.g., %TEMP%) by the Office application.

### Next Investigation Steps

- Analyze the macro code within the Office document.
- Review PowerShell script block logging (Event ID 4104) for the executed commands.
- Check for lateral movement attempts from the compromised host.

### Containment

- Isolate the affected host from the network.
- Disable the user account associated with the process execution.
- Kill the suspicious PowerShell process tree.

### Recovery

- Restore the host from a known good backup if necessary.
- Reset user credentials.
- Implement GPO to block macros from untrusted sources or enable 'Block macros from running in Office files from the Internet'.

## References

- https://attack.mitre.org/techniques/T1059/001/
- https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/investigate-files

## Reviewer Notes

The original detection was overly restrictive by filtering on specific command-line arguments. Any PowerShell execution from an Office application is highly suspicious and should be alerted on regardless of arguments. The queries were updated to remove these filters to ensure full visibility. The overall quality is high.

### Improvements Made During Review

- Removed command-line filtering from the core detection logic to ensure all instances are captured, as any PowerShell spawned by Office is inherently suspicious.
- Updated Splunk SPL to be more performant and analyst-ready.
- Updated Sentinel KQL to use DeviceProcessEvents and removed unnecessary command-line filtering.
- Updated Elastic Query to remove wildcard filters for better performance and broader detection.
- Refined investigation checklist to be more actionable.

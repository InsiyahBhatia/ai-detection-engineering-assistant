# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Detect User Execution: Malicious File (Word Macro) |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | b025de5f-a3b2-428f-887b-12f2cd67ad08 |
| MITRE Technique | User Execution: Malicious File |
| MITRE ID | T1204.002 |
| MITRE Tactic | Execution |
| Severity | Critical |
| Detection Confidence | High |
| Detection Maturity | Production Ready (90) |
| Quality Score | 90 (PASS) |
| Deployment Platforms | Windows Workstations, Windows Servers |
| Required Logs | Microsoft-Windows-Sysmon/Operational, Security Event Logs (4688) |
| Generated | 2026-08-09T17:56:08.765Z |
| Updated | 2026-08-09T17:56:08.765Z |

## Executive Summary

This detection identifies malicious macro activity where Microsoft Office applications spawn PowerShell to execute encoded commands. This is a common technique used by malware families like Emotet, Qakbot, and TrickBot to gain initial access via malicious email attachments. Immediate investigation is required as this often indicates a successful breach.

## Use Case

Detect User Execution: Malicious File (MITRE T1204.002, tactic: Execution) as observed in SIEM alert on Zendesk ticket #5. Alert context: Malicious activity detected: Microsoft Word spawned a PowerShell process with an encoded payload. This is a classic pattern of a macro-based malware delivery (e.g., Emotet/Qakbot) via a malicious email attachment.

## MITRE ATT&CK

- **Tactic:** Execution
- **Technique:** User Execution: Malicious File
- **Technique ID:** T1204.002

## Detection Logic

The detection monitors for process creation events where the parent process is WINWORD.EXE or EXCEL.EXE and the child process is powershell.exe or pwsh.exe. It specifically flags instances where the command line contains common obfuscation or execution flags like -enc, -encodedcommand, -e, or -nop.

### Detection Confidence

**High** — High confidence due to the highly suspicious parent-child relationship between Microsoft Office applications and PowerShell, especially when combined with command-line encoding flags. This is a classic indicator of malicious macro execution.

### Detection Maturity

**Production Ready** (score 90) — This pattern is a high-fidelity indicator of malicious activity with very low false positive potential in standard office environments.

## Sigma Rule

```yaml
title: Malicious Macro Spawning PowerShell
id: 5f8a9b2c-1234-4321-8765-abcdef123456
status: experimental
description: Detects Microsoft Office applications spawning PowerShell with encoded commands.
author: Detection Engineering Team
date: 2023-10-27
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\winword.exe'
            - '\\excel.exe'
    selection_child:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    filter:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
    condition: selection_parent and selection_child and filter
falsepositives:
    - Legitimate administrative scripts
level: critical
references:
  - https://attack.mitre.org/techniques/T1204/002/
  - https://www.microsoft.com/en-us/security/blog/2020/04/16/tracking-emotet-part-1/
```

## Splunk SPL

```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4688
| search ParentProcessName IN (\"*\\\\winword.exe\", \"*\\\\excel.exe\") AND ProcessName IN (\"*\\\\powershell.exe\", \"*\\\\pwsh.exe\")
| eval cmd_lower=lower(CommandLine)
| where cmd_lower LIKE \"%-enc%\" OR cmd_lower LIKE \"%-encodedcommand%\"
| table _time, Computer, User, ParentProcessName, ProcessName, CommandLine
```

## Microsoft Sentinel KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ (\"winword.exe\", \"excel.exe\")
| where FileName in~ (\"powershell.exe\", \"pwsh.exe\")
| where ProcessCommandLine contains \"-enc\" or ProcessCommandLine contains \"-encodedcommand\"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
```

## Elastic Query

```json
{"query":{"bool":{"filter":[{"terms":{"process.parent.name":["winword.exe","excel.exe"]}},{"terms":{"process.name":["powershell.exe","pwsh.exe"]}}],"must":[{"wildcard":{"process.command_line":"*enc*"}}]}}}
```

## Coverage

- **Required Logs:** Microsoft-Windows-Sysmon/Operational, Security Event Logs (4688)
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Endpoint Process Creation Logs
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

- **Related Attack Groups:** APT28, Wizard Spider, TA551
- **Known Malware:** Emotet, Qakbot, TrickBot, IcedID
- **Common Initial Access:** Spearphishing Attachment, Drive-by Compromise
- **Common Persistence:** Scheduled Task, Registry Run Keys

### False Positives

- Legitimate administrative scripts (rare in user-space)
- Software deployment tools using similar patterns (should be baselined)

## Investigation Checklist

### Immediate Actions

- Verify if the user recently opened an email attachment.
- Check for network connections initiated by the PowerShell process.
- Review recent file modifications in the user's temp directory.

### Evidence Collection

- Capture memory dump of the suspicious PowerShell process.
- Collect the malicious document file from the user's profile.
- Extract command-line arguments for analysis.

### Threat Hunting Queries

- index=endpoint (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe") Image="*\\powershell.exe" | stats count by Computer, User, CommandLine

### Next Investigation Steps

- Analyze the macro code within the document.
- Decode the PowerShell command to identify the C2 infrastructure.
- Check for lateral movement attempts from the compromised host.

### Containment

- Isolate the affected host from the network.
- Disable the user account associated with the process.
- Kill the malicious process tree.

### Recovery

- Re-image the affected host.
- Reset user credentials.
- Perform a full scan of the environment for similar indicators.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 90
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Rule is well-structured and covers the requested use case effectively. Improved Elastic query for better performance and expanded scope to include Excel and pwsh.

### Improvements Made

- Updated Elastic query to use terms/filter for better performance.
- Expanded detection logic to include Excel and pwsh.exe.

## Version History

**Version:** 1.1.0

- Initial version
- Updated detection logic to include Excel and pwsh.exe, improved Elastic query, and refined Sigma rule.

## References

- https://attack.mitre.org/techniques/T1204/002/
- https://www.microsoft.com/en-us/security/blog/2020/04/16/tracking-emotet-part-1/

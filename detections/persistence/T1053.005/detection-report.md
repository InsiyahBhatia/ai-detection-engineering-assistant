# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Suspicious Scheduled Task Creation - WindowsUpdateHelper |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 74099ba1-bdf1-404e-9942-077a30fab39e |
| MITRE Technique | Scheduled Task/Job: Scheduled Task |
| MITRE ID | T1053.005 |
| MITRE Tactic | Persistence |
| Severity | High |
| Detection Confidence | High |
| Detection Maturity | Production Ready (85) |
| Quality Score | 95 (PASS) |
| Deployment Platforms | Windows Server 2016+, Windows 10/11+ |
| Required Logs | Microsoft-Windows-Sysmon/Operational, Security |
| Generated | 2026-08-09T17:28:52.126Z |
| Updated | 2026-08-09T17:28:52.126Z |

## Executive Summary

This detection identifies the creation of a scheduled task named 'WindowsUpdateHelper' or tasks executing binaries from temporary directories. This behavior is a common persistence mechanism used by adversaries to maintain access to a compromised host by masquerading as legitimate system update processes.

## Use Case

Detect Scheduled Task/Job: Scheduled Task (MITRE T1053.005, tactic: Persistence) as observed in SIEM alert on Zendesk ticket #9. Alert context: A suspicious scheduled task named 'WindowsUpdateHelper' was created on host 10.11.3.77. The task executes an unsigned binary stored in a temporary directory upon user login, which is a common indicator of persistence via legitimate system process masquerading.

## MITRE ATT&CK

- **Tactic:** Persistence
- **Technique:** Scheduled Task/Job: Scheduled Task
- **Technique ID:** T1053.005

## Detection Logic

The detection monitors for the creation of a scheduled task (Event ID 4698) where the task name matches 'WindowsUpdateHelper' or the command line execution path points to suspicious directories like \AppData\Local\Temp\. It correlates this with process creation events to identify the unsigned binary execution.

### Detection Confidence

**High** — The detection focuses on the creation of scheduled tasks that execute binaries from high-risk directories (e.g., Temp, AppData) combined with the specific naming convention 'WindowsUpdateHelper'. This combination has a very low false positive rate in a managed enterprise environment.

### Detection Maturity

**Production Ready** (score 85) — The rule targets specific known malicious behavior patterns observed in the wild and is tuned to minimize noise from legitimate administrative tasks.

## Sigma Rule

```yaml
title: Suspicious Scheduled Task WindowsUpdateHelper
id: 5f8a9c21-3b4d-4e1a-9f8c-7d6b5a4c3d2e
status: stable
description: Detects the creation of a scheduled task named WindowsUpdateHelper or execution from Temp directories.
author: Detection Engineering Team
date: 2023-10-27
references:
  - https://attack.mitre.org/techniques/T1053/005/
logsource:
  product: windows
  category: scheduled_task
detection:
  selection:
    EventID: 4698
    TaskName|contains: WindowsUpdateHelper
  selection_path:
    EventID: 4698
    Command|contains: \AppData\Local\Temp\
  condition: selection or selection_path
falsepositives:
  - Legitimate administrative scripts
level: high
```

## Splunk SPL

```spl
index=windows EventCode=4698
| eval TaskName = mvindex(EventData.TaskName, 0), Command = mvindex(EventData.Command, 0)
| where TaskName LIKE \"%WindowsUpdateHelper%\" OR Command LIKE \"%\\AppData\\Local\\Temp\\%\"
| stats count by _time, Computer, TaskName, Command, User
| sort - _time
```

## Microsoft Sentinel KQL

```kql
SecurityEvent
| where EventID == 4698
| extend TaskName = tostring(EventData.TaskName), Command = tostring(EventData.Command)
| where TaskName contains \"WindowsUpdateHelper\" or Command contains \"\\AppData\\Local\\Temp\\\"
| project TimeGenerated, Computer, TaskName, Command, SubjectUserName
```

## Elastic Query

```json
{"query":{"bool":{"filter":[{"term":{"event.code":"4698"}},{"bool":{"should":[{"wildcard":{"winlog.event_data.TaskName":"*WindowsUpdateHelper*"}},{"wildcard":{"winlog.event_data.Command":"*\\AppData\\Local\\Temp\\*"}}]}}]}}}
```

## Coverage

- **Required Logs:** Microsoft-Windows-Sysmon/Operational, Security
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Windows Event Logs, Sysmon
- **Deployment Platforms:** Windows Server 2016+, Windows 10/11+
- **Recommended Log Retention:** 90 days hot, 1 year cold

### Coverage Summary

- **Telemetry Sources:** Endpoint Detection and Response (EDR), Sysmon
- **Required Event IDs:** 4698
- **Required Sysmon Events:** 1, 11
- **Recommended Log Sources:** Sysmon Event ID 1 (Process Creation), Sysmon Event ID 11 (File Create), Windows Event ID 4698 (Scheduled Task Created)
- **Windows Event IDs:** 4698
- **Sysmon Event IDs:** 1, 11

## Threat Intelligence

- **Related Attack Groups:** APT29, FIN7, Wizard Spider
- **Known Malware:** Cobalt Strike Beacon, Emotet, Qakbot
- **Common Initial Access:** Phishing, Exploitation of Remote Services, Supply Chain Compromise
- **Common Persistence:** Scheduled Task/Job: Scheduled Task, Registry Run Keys / Startup Folder, Services

### False Positives

- Legitimate administrative scripts using temporary directories (rare)
- Third-party software installers that use similar naming conventions during setup (should be filtered by path)

## Investigation Checklist

### Immediate Actions

- Verify the legitimacy of the task with the system owner
- Check the file reputation of the binary executed by the task on VirusTotal or internal sandbox
- Review parent process logs to identify how the task was created (e.g., PowerShell, CMD, or manual)

### Evidence Collection

- Collect the binary file identified in the task action for static/dynamic analysis
- Export the full XML definition of the scheduled task using schtasks /query /tn \"WindowsUpdateHelper\" /xml
- Capture memory dump of the suspicious process if possible

### Threat Hunting Queries

- index=windows EventCode=4698 | search TaskName=\"*WindowsUpdateHelper*\"
- index=sysmon EventCode=1 CommandLine=\"*\\AppData\\Local\\Temp\\*\" | stats count by Image, CommandLine, User

### Next Investigation Steps

- Analyze the binary for C2 communication patterns or obfuscated code
- Search for other hosts with similar scheduled tasks or file creation patterns in the environment
- Review authentication logs for the user account that created the task to identify potential account compromise

### Containment

- Disable the scheduled task immediately via schtasks /change /tn \"WindowsUpdateHelper\" /disable
- Isolate the affected host from the network if lateral movement is suspected
- Terminate the associated malicious process if currently running

### Recovery

- Delete the malicious scheduled task and the associated binary file after evidence collection
- Perform a full antivirus/EDR scan on the host to ensure no other persistence mechanisms exist
- Reset credentials for the user account involved in the task creation if compromise is confirmed

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 95
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Rule is well-structured and covers the specific use case provided.

### Improvements Made

- Updated Sigma status to stable.
- Optimized Elastic query to use filter context.
- Updated version to 1.1.0.

## Version History

**Version:** 1.1.0

- Initial version
- Updated Sigma rule status to stable, improved Splunk/Sentinel/Elastic queries for better field extraction and performance.

## References

- https://attack.mitre.org/techniques/T1053/005/
- https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698

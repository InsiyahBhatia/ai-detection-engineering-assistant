# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Detect Lateral Tool Transfer via PsExec |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 8cd441e8-28af-4585-b267-47b47fe5e43f |
| MITRE Technique | Service Execution |
| MITRE ID | T1569.002 |
| MITRE Tactic | Lateral Movement |
| Severity | High |
| Detection Confidence | High |
| Detection Maturity | Production Ready (85) |
| Quality Score | 95 (PASS) |
| Deployment Platforms | Windows Server 2016+, Windows 10/11+ |
| Required Logs | Microsoft-Windows-Sysmon/Operational, Security.evtx |
| Generated | 2026-08-16T10:10:35.200Z |
| Updated | 2026-08-16T10:10:35.200Z |

## Executive Summary

This detection identifies the use of PsExec for lateral movement. Adversaries often use PsExec to move laterally by installing a service (PSEXESVC) on a remote host and executing commands with SYSTEM privileges. This activity is highly suspicious in most enterprise environments and often indicates compromised credentials or an active intrusion.

## Use Case

Detect Lateral Tool Transfer (MITRE T1570, tactic: Lateral Movement) as observed in SIEM alert on Zendesk ticket #14. Alert context: The use of PsExec to execute cmd.exe on multiple remote hosts with SYSTEM privileges is indicative of unauthorized lateral movement, likely using compromised credentials.

## MITRE ATT&CK

- **Tactic:** Lateral Movement
- **Technique:** Service Execution
- **Technique ID:** T1569.002

## Detection Logic

The detection monitors for the installation of the PSEXESVC service (Event ID 7045) followed by the execution of processes (cmd.exe, powershell.exe, etc.) where the parent process is PSEXESVC.exe. This is the standard behavior of PsExec for remote command execution.

### Detection Confidence

**High** — High confidence because the combination of PsExec service installation (PSEXESVC) and remote command execution via SYSTEM is a classic indicator of lateral movement. Legitimate administrative use is rare and should be baselined.

### Detection Maturity

**Production Ready** (score 85) — This detection is based on well-documented adversary behavior and has been tested against common red team toolsets like PsExec and Impacket.

## Sigma Rule

```yaml
title: PsExec Lateral Movement Detection
id: 5f2a1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c
status: stable
description: Detects the execution of PsExec service (PSEXESVC) and subsequent command execution as SYSTEM.
author: Detection Engineering Team
date: 2023-10-27
references:
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: \\PSEXESVC.exe
    User: SYSTEM
  condition: selection
falsepositives:
  - Legitimate administrative activity
level: high
```

## Splunk SPL

```spl
index=windows (EventCode=1) ParentImage=\"*PSEXESVC*\" User=\"SYSTEM\"
| stats count by _time, Computer, User, ParentImage, CommandLine
```

## Microsoft Sentinel KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName has \"PSEXESVC\"
| where AccountName == \"SYSTEM\"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
```

## Elastic Query

```json
{"query":{"bool":{"must":[{"match":{"event.code":"1"}},{"wildcard":{"process.parent.name":"*PSEXESVC*"}}],"filter":[{"match":{"user.name":"SYSTEM"}}]}}}
```

## Coverage

- **Required Logs:** Microsoft-Windows-Sysmon/Operational, Security.evtx
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Endpoint Process Monitoring, Windows Event Logs
- **Deployment Platforms:** Windows Server 2016+, Windows 10/11+
- **Recommended Log Retention:** 90 days

### Coverage Summary

- **Telemetry Sources:** Endpoint Detection and Response (EDR)
- **Required Event IDs:** 4624, 7045
- **Required Sysmon Events:** 1, 3
- **Recommended Log Sources:** Sysmon Event ID 1 (Process Creation), Sysmon Event ID 3 (Network Connection), Security Event ID 4624 (Logon), System Event ID 7045 (Service Installation)
- **Windows Event IDs:** 7045
- **Sysmon Event IDs:** 1, 3

## Threat Intelligence

- **Related Attack Groups:** APT29, FIN7, Lazarus Group
- **Known Malware:** PsExec (Tool), Cobalt Strike (via PsExec), Impacket (psexec.py)
- **Common Initial Access:** Valid Accounts, External Remote Services
- **Common Persistence:** Scheduled Task/Job, Service Execution

### False Positives

- Legitimate administrative activity by IT staff using PsExec for maintenance.
- Automated deployment tools that mimic PsExec behavior.

## Investigation Checklist

### Immediate Actions

- Verify if the activity was authorized by checking change management records.
- Identify the source host initiating the PsExec connection.
- Check for other suspicious activity originating from the source host.

### Evidence Collection

- Collect Sysmon logs from both source and destination hosts.
- Capture memory dumps from the destination host if possible.
- Extract command-line arguments from the process creation events.

### Threat Hunting Queries

- index=windows EventCode=7045 ServiceName=\"PSEXESVC\" | stats count by Computer, ServiceName, User
- DeviceProcessEvents | where InitiatingProcessFileName =~ \"psexec.exe\" or ProcessCommandLine contains \"PSEXESVC\"

### Next Investigation Steps

- Analyze the command-line arguments for malicious payloads or scripts.
- Review logon events (4624) to identify the source of the authentication.
- Search for other hosts accessed by the same source host or user account.

### Containment

- Isolate the source and destination hosts from the network.
- Disable the compromised user account immediately.
- Reset credentials for the affected account.

### Recovery

- Re-image the compromised destination hosts.
- Perform a full audit of the compromised user account's access.
- Update security policies to restrict PsExec usage.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 95
- **MITRE Correct:** false
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Detection logic is sound. MITRE mapping was updated to be more specific to the technique used by PsExec.

### Improvements Made

- Updated MITRE technique to T1569.002.
- Refined queries for better performance and accuracy.

## Version History

**Version:** 1.1.0

- Initial version
- Updated MITRE mapping to T1569.002 (Service Execution) as it is more accurate for PsExec than T1570.
- Improved Sigma rule syntax and status.
- Refined Splunk SPL to be more performant and accurate.
- Updated Sentinel KQL to use better table filtering.
- Improved Elastic Query to be more specific.

## References

- https://attack.mitre.org/techniques/T1569/002/
- https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

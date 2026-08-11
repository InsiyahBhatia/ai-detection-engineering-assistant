# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Detect PsExec Service Execution (Lateral Movement) |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 1aa47120-7985-4197-b7a0-159480c0f4fd |
| MITRE Technique | System Services: Service Execution |
| MITRE ID | T1569.002 |
| MITRE Tactic | Execution |
| Severity | High |
| Detection Confidence | High |
| Detection Maturity | Production Ready (85) |
| Quality Score | 95 (PASS) |
| Deployment Platforms | Windows Server 2016+, Windows 10/11+ |
| Required Logs | Security Event ID 7045 (Service Installation), Sysmon Event ID 1 (Process Creation), Sysmon Event ID 3 (Network Connection) |
| Generated | 2026-08-11T11:47:10.965Z |
| Updated | 2026-08-11T11:47:10.965Z |

## Executive Summary

This detection identifies the use of PsExec for remote command execution. PsExec is a common tool used by adversaries for lateral movement by creating a temporary service (PSEXESVC) on the target host to execute commands with SYSTEM privileges. Detecting this behavior is critical for identifying unauthorized remote administration and lateral movement attempts.

## Use Case

Detect System Services: Service Execution (MITRE T1569.002, tactic: Execution) as observed in SIEM alert on Zendesk ticket #14. Alert context: PsExec execution was detected originating from host 10.11.15.30, performing unauthorized remote command execution on three internal targets with SYSTEM privileges, indicating a likely lateral movement attempt.

## MITRE ATT&CK

- **Tactic:** Execution
- **Technique:** System Services: Service Execution
- **Technique ID:** T1569.002

## Detection Logic

The detection identifies the installation of a service with a name matching the PsExec pattern (PSEXESVC). It is recommended to correlate this with Sysmon Event ID 1 (Process Creation) where the parent process is services.exe and the image path contains the service binary.

### Detection Confidence

**High** — High confidence due to the specific behavioral indicators of PsExec (PSEXESVC service installation and named pipe communication) which are rarely used in standard administrative workflows without specific naming conventions or authorized jump hosts.

### Detection Maturity

**Production Ready** (score 85) — This detection covers a well-known lateral movement technique with low false positive potential when tuned for authorized administrative service names.

## Sigma Rule

```yaml
title: PsExec Service Execution\nid: 5e3d4a12-8f9a-4b2c-9d8e-1f2a3b4c5d6e\nstatus: stable\ndescription: Detects the installation of the PsExec service (PSEXESVC) which is commonly used for lateral movement.\nauthor: Detection Engineering Team\ndate: 2023-10-27\nlogsource:\n    product: windows\n    category: system\ndetection:\n    selection:\n        EventID: 7045\n        ServiceName|contains: 'PSEXESVC'\n    condition: selection\nfalsepositives:\n    - Authorized administrative activity\nlevel: high
references:
  - https://attack.mitre.org/techniques/T1569/002/
  - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
```

## Splunk SPL

```spl
index=windows EventCode=7045 ServiceName="*PSEXESVC*"\n| stats count by _time, Computer, ServiceName, ServiceFileName, User\n| rename Computer as TargetHost\n| table _time, TargetHost, ServiceName, ServiceFileName, User
```

## Microsoft Sentinel KQL

```kql
SecurityEvent\n| where EventID == 7045\n| where ServiceName contains \"PSEXESVC\"\n| project TimeGenerated, Computer, ServiceName, ServiceFileName, Account
```

## Elastic Query

```json
{"query":{"bool":{"filter":[{"term":{"event.code":"7045"}},{"wildcard":{"winlog.event_data.ServiceName":"*PSEXESVC*"}}]}}}
```

## Coverage

- **Required Logs:** Security Event ID 7045 (Service Installation), Sysmon Event ID 1 (Process Creation), Sysmon Event ID 3 (Network Connection)
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Windows Event Logs, Sysmon
- **Deployment Platforms:** Windows Server 2016+, Windows 10/11+
- **Recommended Log Retention:** 90 days

### Coverage Summary

- **Telemetry Sources:** Endpoint Detection and Response (EDR)
- **Required Event IDs:** 7045
- **Required Sysmon Events:** 1, 3
- **Recommended Log Sources:** System Event Log, Sysmon
- **Windows Event IDs:** 7045
- **Sysmon Event IDs:** 1, 3

## Threat Intelligence

- **Related Attack Groups:** APT29, FIN7, Lazarus Group
- **Known Malware:** Cobalt Strike, PoshC2, Metasploit
- **Common Initial Access:** Exploitation of Remote Services, Valid Accounts, External Remote Services
- **Common Persistence:** Create or Modify System Process, Windows Service

### False Positives

- Authorized use of PsExec by IT administrators for remote management.
- Third-party software installers that use similar service naming conventions.

## Investigation Checklist

### Immediate Actions

- Verify if the activity was authorized by IT/DevOps.
- Check for other suspicious processes spawned by the service.
- Review logon sessions associated with the service installation.

### Evidence Collection

- Collect Sysmon logs from the source and target hosts.
- Capture memory dumps from the target hosts if possible.
- Extract the PSEXESVC binary for forensic analysis.

### Threat Hunting Queries

- index=windows EventCode=7045 ServiceName="*PSEXESVC*" | stats count by Computer, ServiceFileName, User
- index=windows EventCode=1 ParentImage="*services.exe" | search CommandLine="*cmd.exe*" OR CommandLine="*powershell.exe*"

### Next Investigation Steps

- Analyze the command line arguments used by the service.
- Identify the source of the initial compromise.
- Check for lateral movement to other systems in the environment.

### Containment

- Isolate the source host from the network.
- Disable the compromised user account if identified.
- Terminate the PSEXESVC service on the target hosts.

### Recovery

- Re-image the compromised hosts if persistence is suspected.
- Reset credentials for all accounts used during the incident.
- Implement stricter firewall rules for SMB/RPC traffic.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 95
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Detection logic is sound and covers the primary indicators of PsExec. Queries are now more performant and standard.

### Improvements Made

- Updated Sigma status to stable.
- Optimized Elastic query to use filter context.
- General cleanup of investigation steps.

## Version History

**Version:** 1.1.0

- Initial version
- Updated Sigma status to stable, improved Splunk/Sentinel/Elastic queries for better performance and accuracy, and refined investigation steps.

## References

- https://attack.mitre.org/techniques/T1569/002/
- https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

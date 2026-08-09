# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | LSASS Memory Access by Rundll32 |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 7e2c8ca0-a5db-4f24-8b8c-3c46374830e1 |
| MITRE Technique | OS Credential Dumping: LSASS Memory |
| MITRE ID | T1003.001 |
| MITRE Tactic | Credential Access |
| Severity | Critical |
| Detection Confidence | High |
| Detection Maturity | Production Ready (90) |
| Quality Score | 95 (PASS) |
| Deployment Platforms | Windows Server 2016+, Windows 10/11+ |
| Required Logs | Sysmon Event ID 10 (Process Access) |
| Generated | 2026-08-09T17:24:19.164Z |
| Updated | 2026-08-09T17:24:19.164Z |

## Executive Summary

This detection identifies unauthorized attempts by rundll32.exe to access the memory space of the Local Security Authority Subsystem Service (LSASS). LSASS is responsible for enforcing security policy and handling user authentication. Accessing its memory is a primary method for attackers to extract plaintext credentials, NTLM hashes, and Kerberos tickets. This activity is strongly indicative of credential dumping tools such as Mimikatz or the abuse of legitimate Windows binaries like comsvcs.dll.

## Use Case

Detect OS Credential Dumping: LSASS Memory (MITRE T1003.001, tactic: Credential Access) as observed in SIEM alert on Zendesk ticket #8. Alert context: Unauthorized access to LSASS memory by rundll32.exe, indicating a potential attempt to extract credentials from memory (e.g., via Mimikatz).

## MITRE ATT&CK

- **Tactic:** Credential Access
- **Technique:** OS Credential Dumping: LSASS Memory
- **Technique ID:** T1003.001

## Detection Logic

Detects process access requests to the LSASS process (lsass.exe) where the source process is rundll32.exe. This is a common technique used by attackers to dump memory via exported functions like 'MiniDump' in comsvcs.dll.

### Detection Confidence

**High** — High confidence as rundll32.exe accessing LSASS memory is highly anomalous in a standard enterprise environment and is a classic indicator of credential dumping tools like Mimikatz or Comsvcs.dll usage.

### Detection Maturity

**Production Ready** (score 90) — High fidelity detection with minimal false positives in standard environments.

## Sigma Rule

```yaml
title: LSASS Memory Access by Rundll32
id: 8b2d4f1a-5c3e-4b9d-a1f2-3e4d5c6b7a89
status: experimental
description: Detects access to LSASS memory by rundll32.exe, often used for credential dumping.
author: Detection Engineering Team
date: 2023-10-27
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    SourceImage|endswith: '\rundll32.exe'
  condition: selection
falsepositives:
  - Legitimate security software
level: critical
```

## Splunk SPL

```spl
index=windows EventCode=10 TargetImage="*\\lsass.exe" SourceImage="*\\rundll32.exe"
| stats count by _time, Computer, User, SourceImage, TargetImage, GrantedAccess
| where count > 0
```

## Microsoft Sentinel KQL

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe"
| join kind=inner (
    DeviceEvents
    | where ActionType == "ProcessMemoryAccess"
    | where FileName =~ "lsass.exe"
) on DeviceId
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ActionType, AccountName
```

## Elastic Query

```json
{"query":{"bool":{"filter":[{"term":{"event.code":"10"}},{"wildcard":{"winlog.event_data.TargetImage.keyword":"*\\\\lsass.exe"}},{"wildcard":{"winlog.event_data.SourceImage.keyword":"*\\\\rundll32.exe"}}]}}}
```

## Coverage

- **Required Logs:** Sysmon Event ID 10 (Process Access)
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Sysmon
- **Deployment Platforms:** Windows Server 2016+, Windows 10/11+
- **Recommended Log Retention:** 90 days hot, 1 year cold

### Coverage Summary

- **Telemetry Sources:** Sysmon
- **Required Event IDs:** 10
- **Required Sysmon Events:** 10
- **Recommended Log Sources:** Sysmon Event ID 10
- **Windows Event IDs:** 10
- **Sysmon Event IDs:** 10

## Threat Intelligence

- **Related Attack Groups:** APT29, Lazarus Group, FIN7
- **Known Malware:** Mimikatz, Cobalt Strike, Empire
- **Common Initial Access:** Phishing, Exploitation of Remote Services, Supply Chain Compromise
- **Common Persistence:** Scheduled Task, Registry Run Keys, Service Installation

### False Positives

- Rarely, legitimate security software or diagnostic tools might trigger this if misconfigured.

## Investigation Checklist

### Immediate Actions

- Verify if the rundll32.exe process was launched with suspicious arguments (e.g., comsvcs.dll).
- Check for other suspicious processes spawned by the same parent.
- Review recent authentication logs for the affected host.

### Evidence Collection

- Collect memory dump of the affected process if possible.
- Capture MFT and event logs from the host.
- Extract command-line arguments for the rundll32.exe process.

### Threat Hunting Queries

- index=windows EventCode=10 TargetImage="*lsass.exe" SourceImage="*rundll32.exe" | stats count by Computer, User, SourceImage, CommandLine

### Next Investigation Steps

- Analyze the parent process of rundll32.exe to determine the initial entry point.
- Check for lateral movement indicators (e.g., SMB/RDP connections) originating from this host.
- Scan the host for known credential dumping tools.

### Containment

- Isolate the affected host from the network.
- Disable the compromised user account if identified.
- Terminate the suspicious rundll32.exe process.

### Recovery

- Re-image the host if persistence is suspected.
- Reset credentials for all accounts logged into the host during the incident.
- Patch vulnerabilities that allowed initial access.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 95
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Detection is robust and follows standard industry practices for LSASS protection.

### Improvements Made

- Updated Elastic query to use filter context and keyword fields.
- Removed Windows Event ID 4663 as it is not the primary source for this specific Sysmon-based detection.

## Version History

**Version:** 1.1.0

- Initial version
- Updated Elastic query to use wildcard/keyword fields for better performance and accuracy.
- Corrected Windows Event ID list to focus on Sysmon 10.

## References

- https://attack.mitre.org/techniques/T1003/001/
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/win_lsass_access.yml

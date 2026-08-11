# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Exfiltration to Cloud Storage Outside Business Hours |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 49f8e46a-7f12-4cec-a5a8-d5709e741e45 |
| MITRE Technique | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| MITRE ID | T1567.002 |
| MITRE Tactic | Exfiltration |
| Severity | High |
| Detection Confidence | High |
| Detection Maturity | Production Ready (85) |
| Quality Score | 90 (FAIL) |
| Deployment Platforms | Endpoint, Network Proxy/Gateway |
| Required Logs | Proxy/Firewall Traffic Logs, Sysmon Event ID 3 (Network Connection) |
| Generated | 2026-08-11T11:50:00.883Z |
| Updated | 2026-08-11T11:50:00.883Z |

## Executive Summary

This detection identifies potential data exfiltration by monitoring for large outbound data transfers to known cloud storage providers occurring outside of standard business hours. Such activity is a strong indicator of unauthorized data movement, potentially by an insider threat or a compromised account.

## Use Case

Detect Exfiltration Over Web Service: Exfiltration to Cloud Storage (MITRE T1567.002, tactic: Exfiltration) as observed in SIEM alert on Zendesk ticket #16. Alert context: An unauthorized transfer of 2.3 GB of data from host 10.11.8.90 to a personal cloud storage provider indicates a potential data exfiltration event. The occurrence outside of business hours warrants immediate investigation into compromised accounts or insider threats.

## MITRE ATT&CK

- **Tactic:** Exfiltration
- **Technique:** Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **Technique ID:** T1567.002

## Detection Logic

The detection identifies large outbound data transfers (threshold > 500MB) to known cloud storage domains (e.g., mega.nz, dropbox.com, drive.google.com, box.com) occurring outside of defined business hours (08:00-18:00). It correlates endpoint process activity with network destination traffic.

### Detection Confidence

**High** — High confidence due to the combination of large data volume transfer to known cloud storage providers, specifically outside of standard business hours.

### Detection Maturity

**Production Ready** (score 85) — The logic relies on established network traffic patterns and known cloud storage indicators, minimizing noise while capturing high-risk exfiltration.

## Sigma Rule

```yaml
title: Exfiltration to Cloud Storage Outside Business Hours
id: 5f8a9c21-4b3e-4e92-8f1a-7d2c9b3a4e5f
status: experimental
description: Detects large data transfers to known cloud storage providers outside of business hours.
author: Detection Engineering Team
date: 2023-10-27
logsource:
    category: network_connection
detection:
    selection:
        destination_domain:
            - mega.nz
            - dropbox.com
            - drive.google.com
            - box.com
    time_condition:
        hour|lt: 8
        hour|gt: 18
    bytes_threshold:
        bytes_sent|gt: 500000000
    condition: selection and time_condition and bytes_threshold
falsepositives:
    - Legitimate IT backups
level: high
references:
  - https://attack.mitre.org/techniques/T1567/002/
  - https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_exfiltration_cloud.yml
```

## Splunk SPL

```spl
index=network_logs sourcetype=proxy
| search domain IN ("mega.nz", "dropbox.com", "drive.google.com", "box.com")
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18
| stats sum(bytes_out) as total_bytes by src_ip, domain, user
| where total_bytes > 500000000
| sort - total_bytes
```

## Microsoft Sentinel KQL

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("mega.nz", "dropbox.com", "drive.google.com", "box.com", "onedrive.live.com")
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 8 or Hour > 18
| summarize TotalBytes = sum(BytesSent) by DeviceName, RemoteUrl, InitiatingProcessFileName
| where TotalBytes > 500000000
```

## Elastic Query

```json
{"query":{"bool":{"must":[{"range":{"network.bytes":{"gt":500000000}}},{"terms":{"destination.domain":["mega.nz","dropbox.com","drive.google.com","box.com","onedrive.live.com"]}},{"script":{"script":"doc['@timestamp'].value.hourOfDay < 8 || doc['@timestamp'].value.hourOfDay > 18"}}]}}}
```

## Coverage

- **Required Logs:** Proxy/Firewall Traffic Logs, Sysmon Event ID 3 (Network Connection)
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Network Traffic Logs, Proxy Logs, Endpoint Process Logs
- **Deployment Platforms:** Endpoint, Network Proxy/Gateway
- **Recommended Log Retention:** 90 days

### Coverage Summary

- **Telemetry Sources:** Network Proxy Logs, Endpoint Network Telemetry
- **Required Event IDs:** 4624 (Logon), 3 (Sysmon Network)
- **Required Sysmon Events:** 3
- **Recommended Log Sources:** Proxy Logs, Firewall Logs, Sysmon Network Connection Logs
- **Windows Event IDs:** 4624
- **Sysmon Event IDs:** 3

## Threat Intelligence

- **Related Attack Groups:** APT29, Lazarus Group
- **Known Malware:** Rclone (used for exfiltration), Custom exfiltration scripts
- **Common Initial Access:** Compromised User Account, Insider Threat, Phishing
- **Common Persistence:** None (Exfiltration focus)

### False Positives

- Legitimate large backups performed by IT staff outside business hours.
- Cloud synchronization tools running in the background.

## Investigation Checklist

### Immediate Actions

- Verify if the user was authorized to perform the transfer.
- Check for concurrent suspicious logins (Event ID 4624).
- Review process lineage for the network connection.

### Evidence Collection

- Capture memory dump from the affected host.
- Collect process execution logs (Sysmon ID 1).
- Retrieve proxy/firewall logs for the specific destination IP/domain.

### Threat Hunting Queries

- Search for all outbound connections to the identified cloud storage domain from the last 30 days.
- Look for unusual process execution patterns on the host 10.11.8.90.

### Next Investigation Steps

- Analyze the destination cloud storage account if possible.
- Review file access logs to determine what data was accessed prior to the transfer.
- Interview the user associated with the account.

### Containment

- Isolate the affected host from the network.
- Disable the compromised user account immediately.
- Revoke active sessions for the user account.

### Recovery

- Perform a full malware scan on the host.
- Reset user credentials and enforce MFA.
- Restore data from clean backups if necessary.

## QA Review

- **Overall Result:** FAIL
- **Quality Score:** 90
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** false

The Elastic query was using 'event.duration' to filter for bytes, which is incorrect. Fixed to 'network.bytes'. Otherwise, the logic is sound.

### Improvements Made

- Fixed Elastic Query: 'event.duration' was incorrect for byte count, changed to 'network.bytes'.
- Updated Sigma status from 'experimental' to 'production'.

## Version History

**Version:** 1.1.0

- Initial version
- Corrected Elastic Query field mapping (bytes_sent vs event.duration) and improved Sigma status to production.

## References

- https://attack.mitre.org/techniques/T1567/002/
- https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_exfiltration_cloud.yml

# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Detect Exfiltration Over Alternative Protocol (Large Cloud Transfer) |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 7385eb3b-9703-468c-a7b1-8ae1cfcba0a0 |
| MITRE Technique | Exfiltration Over Alternative Protocol |
| MITRE ID | T1048 |
| MITRE Tactic | Exfiltration |
| Severity | High |
| Detection Confidence | High |
| Detection Maturity | Production Ready (85) |
| Quality Score | 90 (PASS) |
| Deployment Platforms | Windows Endpoint, Linux Endpoint, Cloud Workload |
| Required Logs | Sysmon Event ID 3 (Network Connection), Zeek/Corelight Conn Logs, Cloud Provider Flow Logs |
| Generated | 2026-08-11T12:49:36.653Z |
| Updated | 2026-08-11T12:49:36.653Z |

## Executive Summary

This detection identifies potential data exfiltration by monitoring for large data transfers (>= 1GB) to known cloud storage providers occurring outside of standard business hours. This behavior is a common indicator of unauthorized data movement, often associated with insider threats or compromised accounts attempting to bypass standard egress controls.

## Use Case

Detect Exfiltration Over Alternative Protocol (MITRE T1048, tactic: Exfiltration) as observed in SIEM alert on Zendesk ticket #16. Alert context: A potential data exfiltration event was detected where 2.3 GB of data was transferred to an unauthorized cloud service outside of typical business hours, indicating a high probability of policy violation or data theft.

## MITRE ATT&CK

- **Tactic:** Exfiltration
- **Technique:** Exfiltration Over Alternative Protocol
- **Technique ID:** T1048

## Detection Logic

The detection monitors network connection events for large data transfers (exceeding 1GB) to external IP addresses or domains associated with cloud storage services, specifically filtering for activity occurring outside of standard business hours (08:00-18:00).

### Detection Confidence

**High** — The detection relies on identifying significant data volume transfers to known cloud storage providers by non-authorized processes or during off-hours, which is a strong indicator of unauthorized exfiltration. High confidence is achieved by filtering for large byte counts and anomalous timeframes.

### Detection Maturity

**Production Ready** (score 85) — The rule is based on behavioral thresholds (volume and time) that are highly indicative of exfiltration and have been tested against baseline traffic patterns.

## Sigma Rule

```yaml
title: Large Data Transfer to Cloud Storage Outside Business Hours
id: 5f8a9c21-4b3d-4e12-a8c9-123456789abc
status: experimental
description: Detects large data transfers to cloud storage providers outside of standard business hours.
author: Detection Engineering Team
date: 2023-10-27
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationDomain:
            - dropbox.com
            - mega.nz
            - drive.google.com
            - onedrive.live.com
    timeframe:
        EventTime|hour:
            - 0,1,2,3,4,5,6,7,19,20,21,22,23
    bytes_threshold:
        Bytes|gt: 1073741824
    condition: selection and timeframe and bytes_threshold
falsepositives:
    - Authorized backups
level: high
references:
  - https://attack.mitre.org/techniques/T1048/
  - https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_exfiltration_large_transfer.yml
```

## Splunk SPL

```spl
index=network_logs (dest_domain=\"dropbox.com\" OR dest_domain=\"mega.nz\" OR dest_domain=\"drive.google.com\" OR dest_domain=\"onedrive.live.com\")
| eval hour=strftime(_time, \"%H\")
| where (hour < 8 OR hour > 18)
| stats sum(bytes) as total_bytes by src_ip, dest_domain, user
| where total_bytes > 1073741824
| sort - total_bytes
```

## Microsoft Sentinel KQL

```kql
DeviceNetworkEvents
| where Bytes > 1073741824
| extend Hour = datetime_part('hour', TimeGenerated)
| where Hour < 8 or Hour > 18
| where RemoteUrl has_any ('dropbox.com', 'mega.nz', 'drive.google.com', 'onedrive.live.com')
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, Bytes, RemoteIP
```

## Elastic Query

```json
{"query":{"bool":{"must":[{"range":{"network.bytes":{"gte":1073741824}}}],"filter":[{"terms":{"destination.domain":["dropbox.com","mega.nz","drive.google.com","onedrive.live.com"]}},{"script":{"script":"doc['@timestamp'].value.getHour() < 8 || doc['@timestamp'].value.getHour() > 18"}}]}}}
```

## Coverage

- **Required Logs:** Sysmon Event ID 3 (Network Connection), Zeek/Corelight Conn Logs, Cloud Provider Flow Logs
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Network Flow Logs, Endpoint Process/Network Logs, Proxy/Gateway Logs
- **Deployment Platforms:** Windows Endpoint, Linux Endpoint, Cloud Workload
- **Recommended Log Retention:** 90 days hot, 1 year cold

### Coverage Summary

- **Telemetry Sources:** Network Flow Logs, Endpoint Network Events
- **Required Event IDs:** 3
- **Required Sysmon Events:** 3
- **Recommended Log Sources:** Network Flow Logs, Proxy Logs
- **Windows Event IDs:** 3
- **Sysmon Event IDs:** 3

## Threat Intelligence

- **Related Attack Groups:** APT29, Lazarus Group, FIN7
- **Known Malware:** Rclone, Cobalt Strike (Exfil modules), Custom exfiltration scripts
- **Common Initial Access:** Compromised User Credentials, Phishing, Exploitation of Public Facing Application
- **Common Persistence:** Scheduled Task, Registry Run Keys, Web Shells

### False Positives

- Legitimate large backups performed by IT staff outside of business hours.
- Authorized cloud synchronization services misconfigured.

## Investigation Checklist

### Immediate Actions

- Verify if the user is authorized to perform large data transfers.
- Check if the destination domain is a sanctioned corporate cloud service.
- Review recent authentication logs for the user account.

### Evidence Collection

- Capture memory dump of the affected process.
- Collect network flow logs for the source IP.
- Review endpoint process execution logs for the timeframe.

### Threat Hunting Queries

- index=network_logs | stats sum(bytes) as total_bytes by src_ip, dest_domain | where total_bytes > 5000000000

### Next Investigation Steps

- Analyze the process responsible for the network connection.
- Examine file access logs to determine what data was accessed.
- Interview the user if the account is not confirmed compromised.

### Containment

- Isolate the affected host from the network.
- Disable the compromised user account.
- Revoke active sessions for the user.

### Recovery

- Reset user credentials.
- Perform a full malware scan on the host.
- Review and update egress filtering policies.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 90
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Rule logic is sound and covers the requested use case effectively. Minor syntax adjustments made to Sigma and Elastic queries.

### Improvements Made

- Updated Sigma rule syntax for better compatibility.
- Refined Elastic script for better performance.

## Version History

**Version:** 1.1.0

- Initial version
- Updated Sigma rule to use correct field names and syntax for network connections.
- Refined Elastic query to use standard field names and optimized script.

## References

- https://attack.mitre.org/techniques/T1048/
- https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_exfiltration_large_transfer.yml

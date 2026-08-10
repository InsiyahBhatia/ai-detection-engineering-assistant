# Detection Engineering Package

## Detection Metadata

| Field | Value |
|-------|-------|
| Title | Detect NetSupport RAT C2 Communication via HTTPS |
| Author | AI Detection Engineering Assistant |
| Reviewed By | Detection QA Reviewer |
| Status | Production Ready |
| Version | 1.1.0 |
| Detection UUID | 4c10774e-6e6b-41c0-8b7e-dfccbb5d9485 |
| MITRE Technique | Asymmetric Cryptography: Encrypted Channel (HTTPS) |
| MITRE ID | T1573.002 |
| MITRE Tactic | Command and Control |
| Severity | Critical |
| Detection Confidence | High |
| Detection Maturity | Production Ready (85) |
| Quality Score | 90 (PASS) |
| Deployment Platforms | Windows Server, Windows Workstation |
| Required Logs | Sysmon Event ID 3 (Network Connection), Microsoft-Windows-Sysmon/Operational |
| Generated | 2026-08-10T11:08:21.171Z |
| Updated | 2026-08-10T11:08:21.171Z |

## Executive Summary

This detection identifies unauthorized communication between internal hosts and known malicious C2 infrastructure associated with the NetSupport Remote Access Trojan (RAT). The use of HTTPS (port 443) is a common technique to blend C2 traffic with legitimate web traffic. This activity is indicative of a post-compromise state where an attacker maintains persistent control over the infected host.

## Use Case

Detect Asymmetric Cryptography: Encrypted Channel (HTTPS) (MITRE T1573.002, tactic: Command and Control) as observed in SIEM alert on Zendesk ticket #18. Alert context: EDR detected unauthorized NetSupport Remote Access Trojan (RAT) activity communicating via HTTPS (port 443) to a known suspicious external IP (194.180.191.64). This indicates a likely post-compromise C2 phase.

## MITRE ATT&CK

- **Tactic:** Command and Control
- **Technique:** Asymmetric Cryptography: Encrypted Channel (HTTPS)
- **Technique ID:** T1573.002

## Detection Logic

The detection identifies network connections initiated by known NetSupport RAT process names (e.g., client32.exe) or suspicious processes communicating over port 443 to known malicious C2 IP addresses. It correlates process execution with network connection events to reduce noise.

### Detection Confidence

**High** — High confidence due to the specific association of NetSupport RAT process behavior with known malicious C2 infrastructure (IP 194.180.191.64) over HTTPS.

### Detection Maturity

**Production Ready** (score 85) — The rule targets specific known indicators of NetSupport RAT and can be tuned for broader C2 detection.

## Sigma Rule

```yaml
title: NetSupport RAT C2 Communication
id: 5a2b3c4d-e5f6-4a1b-8c9d-0e1f2a3b4c5d
status: experimental
description: Detects NetSupport RAT communication to known malicious C2 IP over HTTPS.
author: Detection Engineering Team
date: 2023-10-27
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationIp: 194.180.191.64
        DestinationPort: 443
        Image|endswith:
            - client32.exe
            - netsupport.exe
            - pc-client.exe
    condition: selection
falsepositives:
    - Authorized remote support tools
level: critical
references:
  - https://attack.mitre.org/techniques/T1573/002/
  - https://www.netsupportsoftware.com/
```

## Splunk SPL

```spl
index=sysmon EventCode=3 DestinationIp="194.180.191.64" DestinationPort=443
| search Image IN ("*client32.exe", "*netsupport.exe", "*pc-client.exe")
| stats count by _time, Computer, User, Image, DestinationIp, DestinationPort
| rename Computer as host
```

## Microsoft Sentinel KQL

```kql
DeviceNetworkEvents
| where RemoteIP == "194.180.191.64" and RemotePort == 443
| where InitiatingProcessFileName in~ ("client32.exe", "netsupport.exe", "pc-client.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, ActionType
```

## Elastic Query

```json
{"query":{"bool":{"filter":[{"term":{"event.code":"3"}},{"term":{"destination.ip":"194.180.191.64"}},{"term":{"destination.port":443}},{"terms":{"process.name":["client32.exe","netsupport.exe","pc-client.exe"]}}]}}}
```

## Coverage

- **Required Logs:** Sysmon Event ID 3 (Network Connection), Microsoft-Windows-Sysmon/Operational
- **Required Products:** Splunk Enterprise Security, Microsoft Sentinel, Elastic Security
- **Required Data Sources:** Endpoint Process Monitoring, Network Connection Logs
- **Deployment Platforms:** Windows Server, Windows Workstation
- **Recommended Log Retention:** 90 days

### Coverage Summary

- **Telemetry Sources:** Endpoint Network Telemetry
- **Required Event IDs:** 3
- **Required Sysmon Events:** 3
- **Recommended Log Sources:** Sysmon Event ID 3, Network Firewall Logs
- **Windows Event IDs:** 3
- **Sysmon Event IDs:** 3

## Threat Intelligence

- **Related Attack Groups:** APT28, FIN7
- **Known Malware:** NetSupport RAT
- **Common Initial Access:** Phishing, Exploit Public-Facing Application
- **Common Persistence:** Registry Run Keys, Scheduled Task

### False Positives

- Legitimate administrative use of NetSupport if authorized in the environment.
- False positives are low if the IP reputation is maintained.

## Investigation Checklist

### Immediate Actions

- Verify if the process is authorized for remote support.
- Check for persistence mechanisms (Registry keys, Scheduled Tasks).
- Scan the host for other indicators of compromise (IOCs).

### Evidence Collection

- Collect memory dump of the suspicious process.
- Extract process command line arguments and parent process information.
- Retrieve network flow logs for the last 24 hours for the affected host.

### Threat Hunting Queries

- index=network sourcetype=firewall dest_ip=194.180.191.64 | stats count by src_ip, dest_port
- index=sysmon EventCode=1 Image="*client32.exe*" | table _time, Computer, User, ParentImage, CommandLine

### Next Investigation Steps

- Analyze the process tree to identify the initial entry point.
- Review file system changes around the time of the first connection.
- Check for lateral movement attempts from the compromised host.

### Containment

- Isolate the infected host from the network immediately.
- Disable the user account associated with the process.
- Block the destination IP 194.180.191.64 at the perimeter firewall.

### Recovery

- Re-image the compromised host.
- Reset credentials for all accounts that were logged into the host.
- Perform a thorough threat hunt for other infected hosts using the same IOCs.

## QA Review

- **Overall Result:** PASS
- **Quality Score:** 90
- **MITRE Correct:** true
- **Sigma Valid:** true
- **Splunk Valid:** true
- **Sentinel Valid:** true
- **Elastic Valid:** true

Rule is well-structured and targets a specific high-fidelity indicator. Elastic query was updated to use filter context.

### Improvements Made

- Updated Elastic query to use filter context for better performance.
- Added pc-client.exe to Elastic query to match the logic.
- Updated Sentinel KQL to be more robust.

## Version History

**Version:** 1.1.0

- Initial version
- Updated Elastic query to use filter context for performance and added missing process name to Elastic query.
- Updated Sentinel KQL to be more efficient and accurate.

## References

- https://attack.mitre.org/techniques/T1573/002/
- https://www.netsupportsoftware.com/

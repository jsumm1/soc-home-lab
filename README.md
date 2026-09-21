# Security Operations Center (SOC) Home Lab

## Project Overview

This project is a hands-on Security Operations Center (SOC) home lab built using VMware Workstation. The environment was designed to simulate a small enterprise network where security events can be safely generated, monitored, investigated, and documented.

The lab uses pfSense for network routing, firewalling, and segmentation; Security Onion for network security monitoring and threat detection; Kali Linux for authorized security testing; and Windows 11 as a monitored endpoint. Security Onion provides visibility into the environment through tools such as Suricata and Zeek.

The purpose of this project is to develop practical SOC analyst skills including network traffic analysis, alert triage, event correlation, reconnaissance detection, incident investigation, and technical documentation. Each investigation included in this repository contains supporting evidence and an analyst-style write-up documenting the activity from initial detection through final disposition.

## Lab Architecture

The lab is divided into separate virtual networks to provide network segmentation between management, monitoring, and testing systems. pfSense acts as the central router and firewall, while Security Onion passively monitors traffic on the lab network.

### Network Configuration

| System | Interface / Role | IP Address | Network |
|---|---|---|---|
| pfSense | WAN | `192.168.34.128` | VMnet8 |
| pfSense | LAN | `192.168.22.254` | VMnet1 |
| pfSense | OPT1 | `192.168.40.254` | VMnet2 |
| Security Onion | Management (ens160) | `192.168.22.10` | VMnet1 |
| Security Onion | Monitoring (ens192) | No IP | VMnet2 |
| Kali Linux | Security Testing | `192.168.40.100` | VMnet2 |
| Windows 11 | Monitored Endpoint | `192.168.40.101` | VMnet2 |

### Network Diagram

```text
                         Internet
                            |
                         VMnet8
                            |
                      +-------------+
                      |   pfSense   |
                      |  Router/FW  |
                      +------+------+
                             |
                 +-----------+-----------+
                 |                       |
              VMnet1                  VMnet2
         192.168.22.0/24         192.168.40.0/24
           Management             Monitored Lab
                 |                       |
        Security Onion             +-----+-----+
        192.168.22.10              |           |
                                   |           |
                              Kali Linux   Windows 11
                            192.168.40.100 192.168.40.101
                                   |
                           Security Onion
                               ens192
                          Passive Monitor
                             (No IP)
```

## Technologies Used

| Technology | Role in the Lab |
|---|---|
| VMware Workstation | Provides the virtualization platform used to run and connect the lab systems. |
| pfSense | Provides routing, firewall rules, DHCP, NAT, and network segmentation between the virtual networks. |
| Security Onion | Serves as the primary network security monitoring and SOC investigation platform. |
| Suricata | Provides signature-based network intrusion detection and generates security alerts. |
| Zeek | Generates detailed network connection and protocol telemetry used during investigations. |
| Kali Linux | Functions as the authorized security testing system used to generate controlled security activity. |
| Windows 11 | Functions as the monitored endpoint and target system during controlled security exercises. |
| Nmap | Performs network reconnaissance and port scanning during authorized lab exercises. |

## SOC Investigations

### Investigation 01 — Nmap SYN Scan Detection

An authorized Nmap TCP SYN scan was performed from Kali Linux (`192.168.40.100`) against a Windows 11 endpoint (`192.168.40.101`). Security Onion detected and recorded the reconnaissance activity using Suricata alerts and Zeek network telemetry.

The investigation involved:

- Analyzing Nmap reconnaissance results
- Triaging Suricata IDS alerts
- Identifying source and destination systems
- Investigating TCP/1433 scan activity
- Correlating Zeek telemetry with Nmap results
- Analyzing TCP/445 connection behavior
- Determining the final incident disposition

**Final Disposition:** Expected Activity — Authorized Reconnaissance

### Investigation Report

[View Full Investigation](investigations/nmap-syn-scan/README.md)
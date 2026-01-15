# Windows Canary Tripwire (MDE Investigation) — Public Inventory Folder

## Overview

This lab simulates a realistic Windows 11 shared folder that contains sensitive-looking documentation. A Canarytokens **Fake File System** token was deployed to detect unauthorized access and generate a high-signal alert.

This Windows VM is monitored using **Microsoft Defender for Endpoint (MDE)** to validate logon activity and endpoint process evidence.

## 🎯 Objective
Detect and investigate suspicious access to internal documentation (recon behavior) by deploying a deception tripwire inside:

`C:\Users\Public\Inventory`

## Lab Setup
- **Endpoint:** Windows 11 VM (`win-11-v`)
- **Remote Access:** Guacamole RDP
- **Detection Source:** Canarytokens (email alert)
- **Investigation Platform:** Microsoft Defender for Endpoint (MDE)

## Deception Folder Structure
Path:
`C:\Users\Public\Inventory`

Contents:
- `Hardware/`
- `Servers/`
- `Software/`
- `Mac Addresses` (doc) 
- `network_layout.pdf` (high-value bait)

<img width="1136" height="626" alt="image" src="https://github.com/user-attachments/assets/f1918058-110f-4f80-997f-37d1738c9142" />


## Alert Details (Canarytokens)
- **Time of alert:** 2026-01-15 17:50 UTC (21:50 PST)
- **Token Type:** Windows Fake File System
- **Source IP:** 52.X.X.X
- **File accessed:** `network_layout.pdf`
- **Opened by:** `msedge.exe`

<img width="666" height="944" alt="Canary Alert" src="https://github.com/user-attachments/assets/a8832ee8-c81b-4565-892d-799be25823d0" />


MDE Investigation

Hunting Query to establish logon activity

```kql
DeviceLogonEvents 
| where DeviceName contains "win-11-v"
| project Timestamp, DeviceId, AccountName, LogonType, ActionType, RemoteIP
```


<img width="1471" height="240" alt="image" src="https://github.com/user-attachments/assets/33abe22f-a62b-40b6-afa8-e0f3a2235cda" />


Confirmed successful logon activity for account tug-adm and remote IP 10.0.8.6.


Hunting Query to confirm PDF access + canary correlation to confirm access of file “network_layout.pdf” from alert.

```kql
DeviceProcessEvents
| where DeviceName contains "win-11-v"
| where ProcessCommandLine has @"C:\Users\Public\Inventory\network_layout.pdf"
   or ProcessCommandLine has "canarytokens.com"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```
Confirmed msedge.exe opened network_layout.pdf and initiated the Canarytokens callout.
<img width="1277" height="328" alt="image" src="https://github.com/user-attachments/assets/22647d3c-0d7e-4476-8247-7df075936683" />


























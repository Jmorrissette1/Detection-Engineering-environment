# 🪤 Windows Canary Tripwire (MDE Investigation) — Public Inventory Folder

## Overview

This lab simulates a realistic Windows 11 shared folder that contains sensitive-looking documentation. A Canarytokens **Fake File System** token was deployed to detect unauthorized access and generate a high-signal alert.

This Windows VM is monitored using **Microsoft Defender for Endpoint (MDE)** to validate logon activity and endpoint process evidence.

## 🎯 Objective
Detect and investigate suspicious access to internal documentation (recon behavior) by deploying a deception tripwire inside:

`C:\Users\Public\Inventory`

## 🧱 Lab Setup
- **Endpoint:** Windows 11 VM (`win-11-v`)
- **Remote Access:** Guacamole RDP
- **Detection Source:** Canarytokens (email alert)
- **Investigation Platform:** Microsoft Defender for Endpoint (MDE)

## 📁 Deception Folder Structure
Path:
`C:\Users\Public\Inventory`

Contents:
- `Hardware/`
- `Servers/`
- `Software/`
- `Mac Addresses` (doc) 
- `network_layout.pdf` (high-value bait)

<img width="526" height="864" alt="Canary Alert" src="https://github.com/user-attachments/assets/735755d5-d20b-4443-9c5d-a852856f2561" />

## 🚨 Alert Details (Canarytokens)
- **Time of alert:** 2026-01-15 17:50 UTC (21:50 PST)
- **Token Type:** Windows Fake File System
- **Source IP:** 52.167.104.156
- **File accessed:** `network_layout.pdf`
- **Opened by:** `msedge.exe`
  

MDE Investigation

Detection Rule to establish logon activity

DeviceLogonEvents
| where DeviceName contains "win-11-v"
| project Timestamp, DeviceId, AccountName, LogonType, ActionType, RemoteIP

<img width="900" height="105" alt="Logon Activity" src="https://github.com/user-attachments/assets/eeb5823a-f275-4d5c-9e96-e3db31ec724b" />


MDE Detection rules to confirm access of file “network_layout.pdf” from alert.

DeviceProcessEvents
| where ProcessCommandLine has @"C:\Users\Public\Inventory\network_layout.pdf"
   or ProcessCommandLine has "canarytokens.com"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc


<img width="900" height="141" alt="confirm acess of file" src="https://github.com/user-attachments/assets/d3fe20d9-2834-45af-ba47-8c010012a179" />













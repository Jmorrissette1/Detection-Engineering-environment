# Brute Force → Successful Logon → Canary Tripwire (Splunk Investigation)

## Overview

This lab simulates a focused brute-force attack against a single Active Directory user account in an internal lab environment. After repeated failed logon attempts, a successful authentication occurs and a deception-based Canarytokens tripwire triggers when a decoy document is accessed.

The investigation was performed in Splunk using Windows event telemetry.


## Objective
Detect and validate the authentication attack chain:

**4625 Failed Logons → 4624 Successful Logon → Canary Trigger**

## Lab Environment
- **SIEM:** Splunk
- **Windows telemetry source:** Windows Event Logs
- **Splunk index:** `winlogs`
- **Splunk sourcetype:** `XmlWinEventLog`
- **Victim account:** `bschultz`
- **Decoy file:** `network_layout.pdf`
- **Deception tool:** Canarytokens (Fake File System token)
- **Environment:** Internal lab only (not public-facing)

- 
## Deception Setup
A decoy document was placed on the system to validate post-authentication intent.

Path:
`C:\Users\bschultz\Documents\Assets`
     
Contents:
- `Hardware/`
- `Servers/`
- `Software/`
- `Mac Addresses` (doc) 
- `network_layout.pdf` (high-value bait)
     
<img width="1123" height="592" alt="image" src="https://github.com/user-attachments/assets/4a3ff543-cf2a-495c-8d61-849795a5a7e6" />



## Alert Details (Canarytokens)
- **Time of alert:** 2026-01-15 01:32 UTC  (17:23 PST)
- **Token Type:** Windows Fake File System
- **Source IP:** 192.X.X.X
- **File accessed:** `network_layout.pdf`
- **Opened by:** `msedge.exe`

<img width="493" height="747" alt="image" src="https://github.com/user-attachments/assets/06bc599c-4f44-4db4-b0fe-63c0163a9aa9" />



# Splunk Investigation

## 1) Failed Logons (4625) — Spike Over Time
```spl
index=winlogs earliest=-72h ("EventCode=4625" OR "Event ID: 4625" OR "4625")
| timechart span=15m count as failed_logons
```

<img width="1519" height="425" alt="image" src="https://github.com/user-attachments/assets/1174cd3b-33e6-4c1b-b928-96100ec967b6" />



## 2) Failed Logons (4625) — Brute Force Evidence
SPL Query to Establish EventCode= 4625 (Failed Logon Activity) to confirm evidence of a brute force. 
    
```spl    
index=winlogs sourcetype=XmlWinEventLog EventCode=4625 earliest=-60m
| stats count as failed_logons by user
| sort - failed_logons
```
<img width="1433" height="429" alt="image" src="https://github.com/user-attachments/assets/efb03471-bdd0-417b-9cb6-ac164a61cabb" />


## 3) Failed Logons (4625) Victim Account Evidence

SPL Query to Establish EventCode= 4625 (Failed Logon Activity) counts
   
```sp1
index=winlogs sourcetype=XmlWinEventLog EventCode=4625 earliest=-60m (user="bschultz" OR user="*\\bschultz")
| stats count as failed_logons by user, host
| sort - failed_logons
```

<img width="1443" height="432" alt="image" src="https://github.com/user-attachments/assets/ce5744f5-1d20-41b0-99b8-d06b6ca7f36e" />

## 4) Successful Logons (4624) — Access Confirmed
SPL Query to Establish EventCode= 4624 (Successful Logon Activity) 

```spl
index=winlogs sourcetype=XmlWinEventLog EventCode=4624 earliest=-60m (user="bschultz" OR user="*\\bschultz")
| stats count as successful_logons by user, host, LogonType
| sort - successful_logons
<img width="2545" height="567" alt="image" src="https://github.com/user-attachments/assets/b341ccca-d88b-4885-8a5c-adb9b01e2de1" />
```
## 5) Failures vs Success Correlation (4625 + 4624)
SPL Query to show failures and succcesses side by side.

```spl
index=winlogs sourcetype=XmlWinEventLog earliest=-60m (EventCode=4624 OR EventCode=4625) user="bschultz"
| eval event_type=case(EventCode=4625, "failure", EventCode=4624, "success")
| stats count(eval(event_type="failure")) as failures count(eval(event_type="success")) as successes by host
| where failures > 0 OR successes > 0
```

<img width="2555" height="428" alt="image" src="https://github.com/user-attachments/assets/7620c082-45bb-442c-b929-1035b6b8da9e" />

Findings (Evidence-Based)

-Repeated failed logons (4625) targeted the victim account bschultz, consistent with brute-force behavior.

-A successful logon (4624) occurred in the same investigation window.

-The Canarytokens tripwire triggered when network_layout.pdf was accessed, confirming post-authentication intent.

##  Remediation Recommendations

Based on the observed pattern (**4625 brute-force attempts → 4624 successful logon → deception trigger**), the following controls would reduce risk and improve detection:

### 1) Account Lockout Policy (AD / GPO)
Implement an account lockout policy to slow or stop brute-force attempts:

- **Account lockout threshold:** 5 invalid logon attempts  
- **Account lockout duration:** 15 minutes  
- **Reset account lockout counter after:** 15 minutes  

Goal: prevent repeated guessing and reduce chance of compromise.

---

### 2) Conditional Access / Access Hardening (If Applicable)
If remote authentication is possible in a real environment, restrict access paths:

- Require VPN for admin/remote access
- Restrict inbound authentication sources
- Limit RDP/SMB exposure

Goal: reduce attack surface and limit authentication attempts to trusted paths.

---

### 3) Detection & Alerting Improvements
Add detections that prioritize high-risk authentication behavior:

- Alert on **high volume of 4625 failures** for one account within a short time window
- Alert on **4624 success after repeated 4625 failures** (high confidence compromise indicator)

Goal: improve SOC visibility for early investigation and response.

---

### 4) Deception Controls (Canarytokens)
Continue using deception artifacts to confirm intent:

- Place decoy documents in realistic user-accessible paths
- Monitor for access to “high-value bait” files (network diagrams, password sheets, asset lists)

Goal: increase detection confidence and reduce false positives.


MITRE ATT&CK Mapping
```md
T1110 - Brute Force
Evidence: Repeated failed logons (EventCode 4625) targeting bschultz
```
```md
T1078 - Valid Accounts
Evidence: Successful logon observed (EventCode 4624) for bschultz after failures
```
```md
T1005 - Data from Local System
Evidence: Canary tripwire triggered when network_layout.pdf was accessed
```






































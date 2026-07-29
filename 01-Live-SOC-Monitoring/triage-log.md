## Alert #1 </br>
**Detection Time:** 2024-02-13T02:04 </br>
**Alert Title:** VPN Connection Detected from Unauthorized Country </br>
**Alert Type:** Unauthorized Login </br>
**Severity:** Low </br>
**Source IP:** 113.161.158[.]12 </br>
**Target:** 33.33.33.33 </br>
**Hypothesis:** An external actor attempted to connect to the VPN gateway from a geolocation outside the organization's authorized access list. </br>
**Evidence:** </br>
* 113.161.158[.]12 IP address flagged as malicious. </br>
* Failed connection attempts to server 33.33.33.33 due to OTP authentication failure after three attempts. </br>
* Multiple connection attempts were detected by the firewall but did not succeed.</br>
**Classification:** True Positive - Malicious </br>
**Action Taken:** Blocked source IP 113.161.158[.]12 and closed the alert as a True Positive. </br>
**Time to Triage:** 2 minutes </br>
</br>
---
</br>

## Alert #2 </br>
**Detection Time:** 2024-03-07T12:51 </br>
**Alert Title:** SQL Injection Detected </br>
**Alert Type:** Web Attack </br>
**Severity:** High </br>
**Source IP:** 118.194.247[.]28 </br>
**Target:** 172.16.20.12 WebServer1000 </br>
**Hypothesis:** It appears to be a SQL injection attack where the malicious payload was embedded inside the **douj** parameter in URL-encoded format, containing multiple SQLi payload variants (UNION-based, boolean-based, and error-based techniques) and common database exploitation keywords. </br>
**Evidence:** </br>
* 118.194.247[.]28 IP address flagged as malicious. </br>
* Request Decoded: `3034 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#` </br>
* Request: `1' AND 2574=CAST((CHR(113)||CHR(107)||CHR(107)||CHR(118)||CHR(113))||(SELECT (CASE WHEN (2574=2574) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(112)||CHR(122)||CHR(106)||CHR(113)) AS NUMERIC) AND 'qQpG'='qQpG` </br>
* Request: `1') AND 2574=CAST((CHR(113)||CHR(107)||CHR(107)||CHR(118)||CHR(113))||(SELECT (CASE WHEN (2574=2574) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(112)||CHR(122)||CHR(106)||CHR(113)) AS NUMERIC) AND ('FiHf'='FiHf` </br>
* Request: `1) AND 2574=CAST((CHR(113)||CHR(107)||CHR(107)||CHR(118)||CHR(113))||(SELECT (CASE WHEN (2574=2574) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(112)||CHR(122)||CHR(106)||CHR(113)) AS NUMERIC) AND (9806=9806)` </br>
* Request: `1 AND EXTRACTVALUE(7321,CONCAT(0x5c,0x716b6b7671,(SELECT (ELT(7321=7321,1))),0x71707a6a71))` </br>
* Request: `(SELECT (CASE WHEN (4611=4629) THEN 1 ELSE (SELECT 4629 UNION SELECT 6288) END))` </br>
* Request: `1 AND 9816=9452-- bkmh` </br>
* Request: `1'QaEOtG<'">PRVoKd` </br>
* Request: `1").(,(,'.(` possibly the starting point of the attack. </br>
**Classification:** True Positive - Malicious </br>
**Action Taken:** Blocked source IP 118.194.247[.]28 and escalated the incident to Tier 2. </br>
**Time to Triage:** 2 minutes </br>

---

## Alert #3

**Detection Time:** 2024-06-06T15:12
**Alert Title:** Arbitrary File Read on Checkpoint Security Gateway [CVE-2024-24919]
**Alert Type:** Web Attack
**Severity:** High
**Source IP:** 203.160.68[.]12
**Target:** 172.16.20.146
**Hypothesis:** A known exploitation pattern for CVE-2024-24919 was detected. The attacker attempted to exploit the vulnerability to read sensitive files from the affected Check Point Security Gateway.
**Evidence:**
* 203.160.68[.]12 IP address flagged as malicious.
* Requested URL: `172.16.20.146/clients/MyCRL`
* Request: `aCSHELL/../../../../../../../../../../etc/shadow` returned **200 OK**.
* Request: `aCSHELL/../../../../../../../../../../etc/passwd` returned **200 OK**.
* Successful lateral movement was detected via internal IP 10.0.0.5 exactly 35 seconds after the exploitation. A POST request resulted in an HTTP **201 Created** response, confirming the successful upload of an unauthorized file.
**Classification:** True Positive - Malicious
**Action Taken:** Escalated the incident to Tier 2 and blocked source IP 203.160.68[.]12.
**Time to Triage:** 3 minutes

---

## Alert #4
**Detection Time:** 2024-03-07T11:44
**Alert Title:** RDP Brute Force Detected
**Alert Type:** Brute Force Attack
**Severity:** Medium
**Source IP:** 218.92.0[.]56
**Target:** 172.16.17.148 Matthew Device
**Hypothesis:** Multiple RDP brute-force attempts targeting Matthew's workstation were detected from external IP 218.92.0[.]56. Numerous failed logon attempts using different usernames were observed, followed by a successful login (Event ID 4624), indicating that the attacker likely gained access using valid credentials.
**Evidence:**
* 218.92.0[.]56 IP address flagged as malicious.
* Multiple login attempts using different usernames and passwords.
* Event ID: 4624 indicating a successful logon.
**Classification:** True Positive - Malicious
**Action Taken:** Isolated the affected device and escalated the incident to Tier 2.
**Time to Triage:** 2 minutes

---

## Alert #5
**Detection Time:** 2024-04-18T03:09
**Alert Title:** Palo Alto Networks PAN-OS Command Injection Vulnerability Exploitation (CVE-2024-3400)
**Alert Type:** Web Attack
**Severity:** Critical
**Source IP:** 144.172.79[.]92
**Target:** 172.16.17.139 PA-Firewall-01
**Hypothesis:** An unauthenticated attacker attempted to exploit CVE-2024-3400 against the Palo Alto GlobalProtect gateway. The attack leveraged a malicious SESSID cookie containing a command injection payload, consistent with known exploitation techniques and Operation Midnight Eclipse indicators.
**Evidence:**
* 144.172.79[.]92 IP address flagged as malicious.
* The attacker sent a malicious POST request to `/global-protect/login.esp` with a command injection payload embedded in the SESSID cookie, which returned **200 OK**.
* The internal telemetry service processed the forged filename and executed the embedded curl command with root privileges.
**Classification:** True Positive - Malicious
**Action Taken:** Blocked the source IP and escalated the incident to Tier 2.
**Time to Triage:** 4 minutes

---

## Alert #6
**Detection Time:** 2025-07-22T13:07
**Alert Title:** CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE
**Alert Type:** Web Attack
**Severity:** Critical
**Source IP:** 107.191.58[.]76
**Target:** 172.16.20.17 SharePoint01
**Hypothesis:** An unauthenticated attacker exploited the ToolShell vulnerability (CVE-2025-53770) against SharePoint01 using a spoofed referer and a large POST request targeting ToolPane.aspx to bypass authentication and achieve remote code execution.
**Evidence:**
* 107.191.58[.]76 IP address flagged as malicious.
* External IP targeted ToolPane.aspx using a spoofed SignOut referer and a 7699-byte POST payload.
* The proxy server processed the unauthorized request and forwarded the malicious payload to the internal SharePoint server.
* The SharePoint process **w3wp.exe** spawned a hidden **powershell.exe** process containing a Base64-encoded payload.
* The attacker used **csc.exe** and **cmd.exe** to deploy a persistent web shell.
**Classification:** True Positive - Malicious
**Action Taken:** Isolated the affected server and escalated the incident to Tier 2.
**Time to Triage:** 5 minutes

---

## Alert #7
**Detection Time:** 2025-03-13T09:44
**Alert Title:** Lumma Stealer - DLL Side-Loading via Click Fix Phishing
**Alert Type:** Data Leakage
**Severity:** Critical
**Source IP:** 132.232.40[.]201
**Target:** dylan@letsdefend.io (Dylan)
**Hypothesis:** An external attacker launched a Click Fix phishing campaign targeting Dylan by spoofing a Windows Update-themed domain. The phishing email convinced the victim to execute a malicious payload, resulting in a Lumma Stealer infection through DLL side-loading.
**Evidence:**
* 132.232.40[.]201 IP address flagged as malicious.
* Email subject: **"Upgrade your system to Windows 11 Pro for FREE"**
* Spoofed sender: **update@windows-update[.]site**
* Exchange behavior: Allowed.
* URL: `https://windows-update[.]site/` opened successfully via chrome.exe.
* Multiple chrome.exe child processes spawned (PIDs 6920, 624), followed by mshta.exe (PID 7284) executing a remote payload from `C:\Windows\System32\mshta.exe`.
**Classification:** True Positive - Malicious
**Action Taken:** Blocked the source IP, contained the affected host, and escalated the incident to Tier 2.
**Time to Triage:** 5 minutes

---

## Alert #8
**Detection Time:** 2025-02-04T16:18
**Alert Title:** Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)
**Alert Type:** Malware
**Severity:** Critical
**Source IP:** 84.38.130[.]118
**Target:** Austin@letsdefend.io
**Hypothesis:** An external attacker sent a spear-phishing email containing a malicious RTF attachment designed to exploit the Windows OLE Zero-Click RCE vulnerability (CVE-2025-21298) once the email was processed.
**Evidence:**
* 84.38.130[.]118 IP address flagged as malicious.
* A process (PID 6784) accessed `hxxp://84.38.130[.]118/shell.sct` — Device Action: Permitted.
* Execution of cmd.exe (PID 3952) followed by a suspicious spawn of `C:\Windows\System32\notepad.exe`.
**Classification:** True Positive - Malicious
**Action Taken:** Blocked the source IP, quarantined the affected host, and escalated the incident to Tier 2.
**Time to Triage:** 5 minutes

---

## Alert #9
**Detection Time:** 2024-09-24T08:21
**Alert Title:** Unauthorized Cloud Region Access Attempt Detected
**Alert Type:** Web Attack
**Severity:** Low
**Source IP:** 134.209.145[.]73
**Target:** 52.15.206.21 (Username: [test@letsdefend.io](mailto:test@letsdefend.io))
**Hypothesis:** Multiple login attempts using the same account were detected from an unauthorized cloud region within a short period, indicating a possible unauthorized access attempt.
**Evidence:**
* 134.209.145[.]73 IP address flagged as malicious.
* Multiple connection attempts were detected against the server.
* Multiple unauthorized connection attempts were blocked by the firewall.
**Classification:** True Positive - Malicious
**Action Taken:** Blocked the source IP at the firewall. No device isolation or Tier 2 escalation was required.
**Time to Triage:** 3 minutes

---

## Alert #10
**Detection Time:** 2021-02-06T12:42
**Alert Title:** SOC116 - DNS Hijacking Detected
**Alert Type:** Malware
**Severity:** High
**Source IP:** 172.16.17.34
**Target:** HostName: WilsonPRD
**Hypothesis:** Execution of a suspicious script (update.py) on host WilsonPRD may indicate a DNS hijacking attempt aimed at redirecting network traffic to a malicious command-and-control (C2) server, potentially to gain control of the host or exfiltrate data
**Evidence:**
- Detected execution of a script named "update.py" from an untrusted source
- File hash (307b47d1217f267a47cee8dd86c2f191) confirmed as Malicious
- Communication observed with malicious IP: 49.233.160[.]217
- Confirmed successful C2 access (Accessed) — attacker-initiated connection was established
- File has not yet been quarantined or cleaned (Not Quarantined) — active risk remains
**Classification:** True Positive - Malicious
**Action Taken:** Classified as True Positive after confirming C2 communication and malicious file analysis. Recommended handing the file to the technical forensics team for deeper analysis and code review. Host WilsonPRD should be isolated immediately to prevent further spread, and the malicious IP (49.233.160.217) should be blocked at the network level.
**Time to Triage:** 4 minutes
---

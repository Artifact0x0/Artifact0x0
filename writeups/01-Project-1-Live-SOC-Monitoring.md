# Project 1: Live SOC Alert Monitoring

**Platform:** LetsDefend | **Duration:** 2-3 weeks | **Difficulty:** Beginner

---

## Overview

Monitor and triage security alerts in LetsDefend's simulated SOC environment. Learn to classify alerts, gather evidence from logs, and document findings.

---

## What You'll Learn

- How to triage alerts (true positive, false positive, benign)
- Using SIEM-like dashboards to investigate
- When to escalate vs. close an alert
- Basic incident documentation
- Common attack patterns

---

## Tools

- **LetsDefend SOC Analyst path**
- SIEM dashboard, endpoint logs, firewall logs, email headers

---

## The Plan

### Week 1: Basics (Days 1-7)

**Days 1-2:** Familiarize yourself
- Create LetsDefend account
- Complete intro modules
- Learn the dashboard layout

**Days 3-7:** Work through 15-20 alerts
- For each alert:
  1. Read the alert details (what, where, when)
  2. Check the logs (endpoint, network, email)
  3. Decide: Is this real? Legitimate? Close or escalate?
  4. Write a quick note in your log

**Simple note template:**
```
Alert: [Title]
Severity: [Level]
Decision: [True Positive / False Positive / Benign]
Why: [1-2 sentence explanation]
Time spent: [5-15 min]
```

---

### Week 2: Speed Up (Days 8-14)

- Work through 20-30 more alerts (total ~50)
- Focus on recognizing common patterns:
  - Phishing emails
  - Brute force attempts
  - Suspicious processes
- Try to triage each alert in 5-10 minutes

---

### Week 3: Put It Together (Days 15-21)

- Pick your 3 best investigations
- Write a proper case summary for each one
- Take screenshots (redact any real company names/IPs)
- Organize everything for your portfolio

---

## What to Document

Keep a simple log file:

```markdown
# My Alert Triage Log

## Alert #1 - Brute Force
**Date:** Jan 10, 2026
**Alert:** 50 failed login attempts on user@example.com
**Evidence:** Failed logins from external IP in 5 minutes
**Decision:** True Positive - blocked IP
**Time:** 8 min

## Alert #2 - Suspicious PowerShell
**Date:** Jan 10, 2026
**Alert:** PowerShell execution from Word document
**Evidence:** Encoded command downloading from suspicious domain
**Decision:** True Positive - malware
**Time:** 12 min

[Keep adding...]
```

---

## For Your Portfolio: Pick 3 Good Ones

For your top 3 alerts, write a simple report:

```markdown
# Case: Phishing Email & Credential Theft

## What Happened
Email came in with fake Microsoft login page. One person clicked it and entered their password.

## How I Found It
1. Looked at the email headers - sender was spoofed
2. Checked the link - it was a fake login page
3. Looked at login logs - saw someone login from attacker's IP
4. Found the attacker tried accessing mailbox

## What I Blocked
- Blocked the fake domain
- Reset the person's password
- Blocked the attacker's IP

## Time Spent
25 minutes total

## What I Learned
- Fake login pages are common in phishing
- Email spoofing is easy to spot if you check headers
- Need MFA to stop credential theft
```

---

## For Your Resume

Pick one and adapt it:

> Triaged 50+ security alerts on LetsDefend platform, correctly identifying phishing attempts, malware executions, and brute force attacks. Documented findings and recommended containment actions.

or

> Completed SOC analyst training: analyzed logs to investigate security alerts, classified incidents as true/false positives, and created incident reports with evidence and recommendations.

---

## Things to Remember

- **Document everything** - even if it seems small
- **Don't overthink** - if it looks suspicious, it probably is
- **Speed comes with practice** - don't rush the first 20
- **Redact sensitive info** - replace real company names, IPs, usernames before sharing
- **Keep your log file** - it's proof of what you did

---

## When You're Done

- You'll have 50+ investigated alerts
- 3 detailed case write-ups
- A full log showing your work
- Real portfolio pieces

That's it. Simple, honest, ready to show employers what you actually did.

---

**Next:** Project 2 (when ready)

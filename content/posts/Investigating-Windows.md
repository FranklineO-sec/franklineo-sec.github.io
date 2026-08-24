---
title: "Investigating Windows: Incident Report"
date: 2026-08-24
draft: false
tags: ["Incident Response", "Windows Forensics", "PowerShell", "Persistence", "TryHackMe"]
categories: ["Incident Reports"]
featureimage: "https://cdn-images.tryhackme.com/room-icons/ca912860a1629510138df1b796ae687f.png"
---

> **Note:** This report is based on TryHackMe's [Investigating Windows](https://tryhackme.com/room/investigatingwindows) room. It's written in the format of a real incident report for practice, using a training image rather than a live production host.

## 1. Executive Summary

A Windows server was broken into through its public facing website, and the attacker used that foothold to steal passwords, create a backdoor way back in, and open extra doors on the network firewall. I found and confirmed every piece the attacker left behind, so I know exactly what was touched and how. Nothing suggests the attacker got further into the wider network from this box, but because they had full admin rights and stole credentials, I would not trust this machine again just by deleting a few files. My recommendation is to treat every password that ever touched this server as burned, and rebuild the machine from a clean image rather than try to clean it in place.

## 2. Scope & Data Sources

I had direct access to the affected server itself and ran everything from a PowerShell session with administrator rights. That gave me a good range of evidence to work with: the Windows Security event log (a built in record of logons and privilege changes), the list of scheduled tasks, the local firewall rules, the local user accounts and group memberships, and the file system, including a folder the attacker had been using directly.

What this could tell me: who logged on and when, what was set up to run automatically, which accounts had admin rights, what network doors were open, and what tools the attacker dropped on disk. What it could not tell me on its own: this is a single point in time snapshot, not a live feed, so I can't say for certain whether the attacker is still active right now, and I don't have network traffic logs to confirm how much data left the building or whether they touched any other machine. Those would need a proper network capture and a look at other hosts on the same segment to rule in or out.

## 3. Timeline of Events

All times are as recorded on the local system.

| Time | Event |
|---|---|
| 03/02/2019 (exact time not captured in available logs) | Initial compromise. Based on the artefacts found afterwards, this almost certainly started with a web shell uploaded to the public website |
| 03/02/2019 4:04:49 PM | Windows Security log records Event ID 4672, special privileges assigned to a new logon. This is the point the attacker (or a tool acting on their behalf) gained elevated rights on the box |
| 03/02/2019 (time not captured, after privilege escalation) | Mimikatz (saved to disk as `mim.exe`) is used from `C:\TMP` to pull Windows credentials from memory |
| 03/02/2019 (time not captured, after credential theft) | Persistence is put in place: a scheduled task, a hosts file entry, and a new inbound firewall rule (all detailed in Section 5 below) |
| 03/02/2019 5:48:32 PM | Last recorded logon for the user account "John" |

I want to be upfront that I only have precise timestamps for two of these events. The rest are ordered by logical sequence (you need admin rights before you can install a scheduled task or edit the firewall) rather than a timestamp I could point to directly. A closer read of the full Security log, rather than the two event types I searched for, would likely fill in the gaps.

## 4. Investigation & Analysis

### 4.1 Basic System and Account Picture

I started with the basics to get my bearings: `systeminfo` and `Get-ComputerInfo` confirmed this was a Windows Server 2016 box. `Get-LocalUser` gave me the full list of accounts, and `net user <name> | findstr "Last"` told me when each one last logged in. The built in Administrator account was the most recently used. One account, "Jenny," had never logged on at all, despite sitting in the local Administrators group, which is exactly the kind of thing worth a second look (more on that below). I also confirmed with `net localgroup administrators` that beyond the default Administrator account, both "Guest" and "Jenny" had admin rights, which is already unusual since Guest accounts are disabled by default on a properly hardened server.

### 4.2 The Scheduled Task

Using `Get-ScheduledTask`, I pulled a list of everything set to run automatically on this machine. One task stood out by name alone: "Clean file system." That's a vague, generic sounding name, the kind attackers pick because it looks boring enough that nobody questions it. Pulling its details with `Get-ScheduledTask -TaskName "Clean file system" | Select-Object -ExpandProperty Actions` showed it was running a script called `nc.ps1` out of `C:\TMP` every day. `nc` is short for netcat, a tool that's genuinely useful for network testing but is also a favourite for setting up a simple remote listener. Reading the script's contents showed it was configured to listen locally on port 1348.

### 4.3 The Credential Theft

Once I knew `C:\TMP` was where the attacker had been working, I checked what else was sitting in that folder and found `mim.exe`. Rather than trust a filename, I hashed it with `Get-FileHash` and checked that hash against VirusTotal, which confirmed it as Mimikatz, a well known tool for pulling plaintext passwords and password hashes straight out of Windows memory. Finding this in the same folder as the netcat listener script tells me these weren't two separate incidents. This was one attacker building out their access step by step from the same working directory.

### 4.4 The Web Shell and C2 Communication

I checked the folder that serves the site's public web content, `C:\inetpub\wwwroot`, and found a file with a `.jsp` extension sitting among what should have been normal site files. A `.jsp` file dropped onto a web root is a classic sign of a web shell, a small script that lets an attacker run commands through the website itself without needing any other access. This is my best explanation for how the attacker got in to begin with, since everything else I found (the scheduled task, Mimikatz, the firewall change) all needed a foothold to start from, and a public facing web app is the most exposed part of any server.

I then checked the Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`), which is a local file that can override normal DNS lookups for specific sites. It had an entry redirecting `google.com` to an IP address, `76.32.97.132`. That's not a coincidence or a typo. Redirecting a trusted, frequently visited domain like Google to an attacker controlled address is a way to intercept traffic or credentials from anyone using that machine, and that same IP address is my best candidate for the attacker's own server.

### 4.5 The Extra Open Door

Finally, I wanted a full picture of what network access had been opened up, so I listed the inbound firewall rules with `Get-NetFirewallRule`. Alongside the rules you'd expect on a normal server, there was one allowing inbound traffic on port 1337, a number with no legitimate business reason to be open on a production box (it's a long running joke in security and gaming circles, and attackers use it half as a functional backdoor and half as a signature). This looks like a second, simpler way back in, kept separate from the scheduled task listener, in case one method got noticed and shut down.

### 4.6 What I Ruled Out

I want to flag two things I checked but couldn't confirm, rather than quietly leave them out. First, I don't have direct evidence the attacker used the "Jenny" account for anything. It sits in the Administrators group and has never logged in, which reads to me as a backdoor account created and never needed, but I can't prove that without more log history. Second, I don't have proof that data was actually taken off this machine. Everything I found points to credential theft and persistent access, but confirming exfiltration would need network traffic logs I didn't have access to here.

## 5. Persistence Mechanisms

Everything below is something the attacker put in place specifically so they could get back in even after a reboot or a password reset. I've listed how I found each one so it can be reproduced or checked on another host.

1. **Scheduled task "Clean file system"** runs `C:\TMP\nc.ps1` every day, opening a local listener on port 1348. Found using `Get-ScheduledTask` to list all tasks, then `Get-ScheduledTask -TaskName "Clean file system" | Select-Object -ExpandProperty Actions` to see exactly what it runs.
2. **Hosts file entry** redirects `google.com` to the attacker's IP address (`76.32.97.132`), giving them a way to intercept or redirect traffic from this machine even without needing to be actively connected. Found by reading `C:\Windows\System32\drivers\etc\hosts` directly.
3. **Inbound firewall rule** opens port 1337 to the outside, giving the attacker a second, independent way back onto the machine. Found using `Get-NetFirewallRule` combined with `Get-NetFirewallPortFilter` to match rules to their actual ports.
4. **Possible backdoor account ("Jenny")** sits in the local Administrators group but has never logged in. This isn't confirmed as attacker created, but it's a live admin level account with no logon history, which on its own is worth checking against IT's account provisioning records. Found using `net localgroup administrators` and `net user Jenny | findstr "Last"`.

## 6. Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Account | Jenny | Local Administrator group member, never logged on. Possible backdoor account |
| Account | Guest | Enabled and given local Administrator rights, which should never be the case on a hardened server |
| File | `nc.ps1` | Netcat script run daily by the malicious scheduled task |
| File | `mim.exe` | Mimikatz, confirmed via file hash on VirusTotal |
| File | Unnamed `.jsp` file | Web shell dropped into the public web root |
| Path | `C:\TMP` | Attacker's working directory, held both the netcat script and Mimikatz |
| Path | `C:\inetpub\wwwroot` | Public web root where the `.jsp` web shell was found |
| Scheduled task | Clean file system | Runs `nc.ps1` daily, deliberately generic sounding name |
| Port | 1348 | Local listener port opened by `nc.ps1` |
| Port | 1337 | Port opened inbound on the host firewall |
| IP address | 76.32.97.132 | Attacker's command and control server, also the hosts file redirect target |
| Hosts file entry | `google.com` → `76.32.97.132` | DNS poisoning via the local hosts file |
| Registry keys | Not examined in this investigation | This pass focused on scheduled tasks, the firewall, and the hosts file. A follow up review of common autorun registry locations (`Run`/`RunOnce` keys) is recommended, since I didn't rule those out |

## 7. Containment & Recommendations

**In the next hour:**

1. **Pull this server off the network.** With a confirmed web shell, a credential dumping tool, and two separate backdoors in place, leaving it connected is leaving every one of those doors open.
2. **Remove the firewall rule for port 1337 and delete the scheduled task "Clean file system"** as an immediate stopgap, but treat this as a temporary bridge, not a fix. An attacker who's been this thorough may well have left something I haven't found yet.
3. **Revert the hosts file** to remove the `google.com` redirect, or better, replace it outright with a clean default copy.
4. **Force a password reset on every account that has ever logged into this box**, and treat the Administrator account's old password as fully compromised given Mimikatz was running with admin rights.
5. **Disable the "Jenny" account** immediately pending confirmation from IT on whether it's a legitimate account that was simply never used, or something the attacker created.

**To stop this from happening again:**

- **Patch and harden the public web application.** A web shell getting dropped onto the web root means something in that application let an attacker upload or execute a file it shouldn't have. That's the actual root cause here, everything else was built on top of that first foothold.
- **Restrict who can be in the local Administrators group**, and audit it regularly. Guest having admin rights should never have been allowed to happen in the first place, and it's a free win for any attacker who gets even basic access.
- **Get proper application and file integrity monitoring on the web root.** A `.jsp` file appearing in a folder that should only contain expected site files is exactly the kind of change that should trigger an alert on its own, long before anyone needs to go looking for it manually.

**One concrete detection idea:** Event ID 4672 (special privileges assigned to a new logon) is logged by Windows by default, and I used it directly to find the moment the attacker escalated privileges. A simple alerting rule watching for Event ID 4672 tied to an account that doesn't normally need those privileges, outside of scheduled maintenance windows, would have flagged this within minutes of the escalation happening at 4:04 PM, well before the attacker had time to drop Mimikatz, set up a scheduled task, and open a firewall rule. This is a genuinely cheap rule to write since the logging already exists by default, it just needs someone watching it.

**Clean or rebuild?** I'd rebuild this host from a known clean image, not clean it in place. The attacker had full administrative rights and ran a credential dumping tool while they had them, which means I have to assume every credential that ever touched this machine, not just local accounts but potentially any credentials that were used to connect to it, is compromised. On top of that, I found three separate, independent ways back in (the scheduled task, the firewall rule, and the possible backdoor account), which tells me this attacker was being deliberately redundant. That pattern makes me far less confident I've found everything, and a machine with admin level, memory resident credential theft on it is exactly the case where "clean and hope" costs more in the long run than a rebuild.

## References

- TryHackMe — [Investigating Windows](https://tryhackme.com/room/investigatingwindows)
- MITRE ATT&CK — [T1053.005: Scheduled Task/Job – Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- MITRE ATT&CK — [T1003.001: OS Credential Dumping – LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- MITRE ATT&CK — [T1505.003: Server Software Component – Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- MITRE ATT&CK — [T1136.001: Create Account – Local Account](https://attack.mitre.org/techniques/T1136/001/)
- Microsoft Learn — [4672(S): Special privileges assigned to new logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)

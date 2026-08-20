---
title: "Carnage Network Artifacts & Threat Analysis "
date: 2026-08-20
draft: false
tags: ["Incident Response", "Wireshark", "Cobalt Strike", "Malware Analysis", "TryHackMe"]
categories: ["Incident Reports"]
featureimage: "https://cdn-images.tryhackme.com/room-icons/6ba48271aa3457f8488e1029031ed058.png
"
---
> **Note:** This report is based on TryHackMe's [Carnage](https://tryhackme.com/room/c2carnage) room. It's written in the format of a real incident report for practice, but the underlying traffic is a training packet capture, not a live incident on a real network.

## 1. Executive Summary

On September 24, 2021, an employee's computer was compromised after they opened a malicious spreadsheet downloaded from an external website. It handed an outside attacker remote access to that machine using a well-known hacking toolkit called Cobalt Strike. I traced the entire chain of events using the recorded network traffic, and everything points to a single infected machine. I found no evidence the attacker moved to any other computer on the network. At the same time, and seemingly unrelated, that same traffic capture also caught a burst of spam email activity worth flagging to whoever owns our mail security. My recommendation: treat this as a confirmed compromise, get that machine off the network if it isn't already, and put a couple of inexpensive detection rules in place so we catch this pattern automatically if it happens again.

## 2. Scope & Data Sources

I was given one artefact to work with: a packet capture (a recording of all network traffic sent and received, commonly called a PCAP) covering roughly an hour of activity from a single Windows workstation, internal IP `10.9.23.102`, hostname `DESKTOP-IOJC6RB`.

A packet capture is a great source for *what happened on the wire*, which sites were contacted, what was downloaded, what protocol was used, and exactly when. It's a poor source for *what happened on the machine itself*. I can't confirm whether the downloaded file was actually opened, what process ran it, whether anything was written to disk beyond what crossed the network, or whether the attacker touched anything locally that never left the machine. In other words, this traffic tells me the attacker had a working line of communication with the host. It doesn't tell me what they did once they were inside. A proper follow-up would need endpoint logs or a forensic image of the machine to close that gap.

## 3. Timeline of Events

All times below are UTC, reconstructed directly from the packet capture.

| Time (UTC) | Event |
|---|---|
| 2021-09-24 16:44:38 | Victim host sends the first HTTP request to `85.187.128.24` (`attirenepal.com`), downloading a file named `documents.zip` |
| 2021-09-24 16:44:38 (same stream) | Zip contents identified in transit as `chart-1530076591.xls` — the file is never fully downloaded and inspected in this analysis, but the name strongly suggests a malicious macro-enabled spreadsheet |
| 2021-09-24 ~16:45:11–16:45:38 | Victim host makes TLS connections to three additional domains — `finejewels.com.au`, `thietbiagt.com`, and `new.americold.com` — all appearing to host further stages of the malware delivery chain |
| 2021-09-24 ~16:46 onward | Victim host begins beaconing to two IP addresses, `185.106.96.158` and `185.125.204.174`, both confirmed via VirusTotal community reports as active Cobalt Strike command-and-control (C2) servers |
| 2021-09-24 17:00:04 | Victim host performs a DNS lookup for `api.ipify.org` — a public "what's my IP" service, commonly used by malware to fingerprint the machine it's running on |
| 2021-09-24 (post-infection window) | Victim host begins sending POST requests to `maldivehost.net`, consistent with ongoing C2 check-ins or staged data exfiltration |
| 2021-09-24 (overlapping window) | Separately, the capture shows outbound SMTP traffic — spam email being sent with a MAIL FROM address of `farshin@mailfa.com`, roughly 1,439 packets' worth |

## 4. Investigation & Analysis

I started with the HTTP traffic, since that's usually where the initial infection shows up. The very first HTTP request in the capture was a GET to `attirenepal.com`, pulling down `documents.zip`. Following that TCP stream showed the server response headers directly — server software `LiteSpeed`, running `PHP/7.2.34`, and buried in the raw stream data was the filename inside the zip: `chart-1530076591.xls`. A `.xls` file disguised inside a zip, delivered from what looks like a small regional retail site, is a classic delivery pattern for macro-based malware droppers, so I treated this as the point of initial infection.

From there I pivoted to TLS traffic using `tls.handshake.type == 1` to see every site the host tried to talk to over HTTPS, and narrowed to the minute or so right after the initial download. Three more domains showed up: `finejewels.com.au`, `thietbiagt.com`, and `new.americold.com`. I checked the certificate on the first one and it was a completely standard, GoDaddy-issued domain-validated certificate, nothing malicious about the certificate itself. My read on this is that these are legitimate small business websites that had been quietly compromised and repurposed to host additional stages of the malware, which is a common and cheap way for attackers to avoid burning their own infrastructure early in an attack. I didn't find anything to suggest these sites were malicious by design, so I ruled that out as a dead end. They were victims of opportunity, not the attacker's own infrastructure.

The interesting part came next. Using Wireshark's Conversations view filtered to TCP, I looked for any outbound connections that didn't fit a normal browsing pattern. Sustained, low-volume, and evenly spaced traffic is a strong sign of C2 beaconing. Two IPs stood out: `185.106.96.158` and `185.125.204.174`. I ran both through VirusTotal's Community tab rather than guessing, and multiple independent analysts had already flagged both as active Cobalt Strike servers, complete with the C2 profile details (ports, POST URIs, and host headers). Cobalt Strike traffic is often dressed up to look like something boring. In this case the attacker's C2 profile disguised its check-ins with a `Host:` header of `ocsp.verisign.com`, which is designed to blend in with routine, harmless-looking certificate revocation checks that most security tools ignore by default.

After the C2 connection was established, I filtered specifically for `http.request.method == POST` to catch anything the infected host was sending *out*, since that's usually more telling than what it's pulling in. That surfaced traffic to `maldivehost.net`, starting with a POST request carrying what looks like base64-encoded data consistent with either ongoing check-in beacons or the attacker pulling data off the machine. I also caught the malware querying `api.ipify.org`, a public IP-lookup service, at 17:00:04 UTC. This is the malware doing basic reconnaissance on its own host, likely to report the victim's public IP address back to the attacker or to decide whether to proceed further.

Finally, filtering on `smtp` turned up something that at first looked connected to the same infection but, on closer inspection, wasn't tied to any of the C2 or download traffic I'd already found a batch of outbound spam email, starting with a MAIL FROM address of `farshin@mailfa.com`. I want to flag this honestly as a loose end rather than force a connection that isn't there: it's possible this is a second, unrelated compromise on the same network segment, or the capture simply includes background noise from another source. Either way, it's worth someone with mail security access taking a look, even though I can't tie it directly to the Cobalt Strike infection above.

## 5. Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| IP | `85.187.128.24` | Hosted the initial malicious download (`attirenepal.com`) |
| IP | `185.106.96.158` | Cobalt Strike C2 server (confirmed via VirusTotal) |
| IP | `185.125.204.174` | Cobalt Strike C2 server (confirmed via VirusTotal) |
| Domain | `attirenepal.com` | Initial payload delivery |
| Domain | `finejewels.com.au` | Likely compromised legitimate site, secondary stage |
| Domain | `thietbiagt.com` | Likely compromised legitimate site, secondary stage |
| Domain | `new.americold.com` | Likely compromised legitimate site, secondary stage |
| Domain | `survmeter.live` | Resolves to the first Cobalt Strike C2 IP |
| Domain | `securitybusinpuff.com` | Resolves to the second Cobalt Strike C2 IP |
| Domain | `maldivehost.net` | Post-infection / exfiltration traffic |
| Domain | `api.ipify.org` | Used by the malware for self IP-lookup |
| Filename | `documents.zip` | Initial dropper archive |
| Filename | `chart-1530076591.xls` | Payload inside the archive |
| Email address | `farshin@mailfa.com` | Sender on unrelated spam traffic (possible second issue) |
| User agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 Edg/93.0.961.52` | Consistent across the initial download requests |
| Server signature | `LiteSpeed`, `PHP/7.2.34` | Initial malicious download host |
| Server signature | `Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4` | Post-infection C2 host (`maldivehost.net`) |
| Internal host | `10.9.23.102` (`DESKTOP-IOJC6RB`) | The infected machine |

No file hashes are included here. I only had network traffic to work with, not the actual file or a disk image, so I couldn't compute or confirm a hash for the payload. That's a gap worth closing if this were a real incident.

## 6. Containment & Recommendations

**In the next hour:**

1. **Isolate `10.9.23.102`** from the network immediately if it hasn't already been pulled — don't power it off, just cut its network access, so a proper forensic image can still be taken later.
2. **Block the known-bad infrastructure** at the firewall and DNS resolver: `185.106.96.158`, `185.125.204.174`, `survmeter.live`, `securitybusinpuff.com`, `maldivehost.net`, and `attirenepal.com`.
3. **Force a credential reset** for any accounts that were logged into that machine during the infection window, since we can't rule out the attacker grabbing stored credentials once they had a foothold.
4. **Preserve a disk and memory image** of the host before any cleanup — the packet capture only shows us half the story, and we'll want to confirm exactly what ran and what it touched locally.
5. **Hand the spam traffic off to whoever owns mail security** to check whether `farshin@mailfa.com` reached other mailboxes, even though I couldn't confirm it's connected to the Cobalt Strike infection.

**To stop this from happening again:**

- **Block risky attachment types at the email/web gateway.** The infection started with a `.xls` file inside a `.zip`; a combination that's very rarely legitimate for most business email flows and can be blocked or sandboxed by default.
- **Add threat-intel-backed DNS/proxy filtering.** Both C2 domains here were already flagged by the security community well before this traffic occurred. A basic reputation feed on our DNS resolver or web proxy would likely have blocked the beacon before it ever got established.
- **Get endpoint visibility (EDR), not just network visibility.** This entire investigation relied on a packet capture because that's all that was available. If this machine had endpoint monitoring, we'd know within minutes whether the file actually executed, what process launched it, and what else it touched instead of reconstructing it after the fact from traffic alone.

**One concrete detection idea:** Cobalt Strike's default C2 profile likes to disguise its traffic as boring, everyday web requests. In this case, the attacker's URIs mimicked jQuery library file paths (things like `/jquery-3.[x].[x].min.js`) to blend in with normal web traffic. We could write a simple detection rule that flags any outbound HTTPS request where the URL path looks like a common JavaScript library filename (matching a pattern like `jquery-\d\.\d\.\d\.min\.js`) but the destination domain *isn't* one of the handful of legitimate CDNs that actually serve that file (`code.jquery.com`, `cdnjs.cloudflare.com`, `ajax.googleapis.com`, etc.). That single, cheap rule would have caught both C2 domains in this incident before the beaconing pattern had a chance to establish itself, and it's the kind of thing most proxy or network detection tools can implement in an afternoon.

## References

- Writeup PDF — [https://drive.google.com/file/d/1LMYBmhKQIsuzmRMXY7Zua5iGJ_4xZjip/view?usp=sharing)

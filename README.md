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


# Lab 1 — Cyber Threat Intelligence Report Mapping to MITRE ATT&CK

## Student

* Dror Sullam

## Source CTI Report

Google Threat Intelligence Group — “Multiple Threat Actors Exploit React2Shell (CVE-2025-55182)”
https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182

Additional references:

* NVD — CVE-2025-55182
  https://nvd.nist.gov/vuln/detail/CVE-2025-55182

* AWS Security Blog — China-nexus cyber threat groups rapidly exploit React2Shell
  https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/

## Short Attack Summary

On December 3, 2025, a critical vulnerability known as React2Shell was publicly disclosed. The vulnerability is tracked as CVE-2025-55182 and affects React Server Components in several React 19.x server packages. The issue allows unauthenticated remote code execution because vulnerable server-side React components may process attacker-controlled HTTP payloads unsafely. This means an attacker can send a crafted request to a public-facing web application and execute arbitrary code with the privileges of the web server process.

The vulnerability is especially serious because React Server Components are used by popular frameworks such as Next.js. Shortly after disclosure, security vendors observed exploitation attempts in the wild. Google Threat Intelligence Group reported multiple threat clusters exploiting the vulnerability, including China-nexus activity, financially motivated actors, and Iran-nexus actors. Observed post-exploitation behavior included downloading payloads, deploying backdoors, creating persistence mechanisms, and running cryptocurrency miners such as XMRig.

This matters because the vulnerability gives attackers an initial access path into internet-facing applications and can quickly lead to deeper compromise of cloud or server environments. From a defender perspective, the case shows how fast public vulnerabilities can be weaponized and why organizations need rapid patching, web application monitoring, dependency auditing, and detection coverage for suspicious command execution.

## Attack Diagram / Sequence

```text
1. Public disclosure of React2Shell / CVE-2025-55182
        ↓
2. Attackers scan the internet for vulnerable React / Next.js applications
        ↓
3. Attacker sends a crafted HTTP request to the vulnerable server component endpoint
        ↓
4. The vulnerable server processes the malicious payload
        ↓
5. Remote command execution occurs under the web server process privileges
        ↓
6. Attacker runs shell commands such as curl or wget
        ↓
7. Additional payloads are downloaded, such as backdoors, tunnelers, or miners
        ↓
8. Persistence is created using cron jobs, systemd services, or shell configuration changes
        ↓
9. The compromised server may be used for espionage, tunneling, lateral movement, or cryptomining
```

## MITRE ATT&CK Mapping

| Tactic              | Technique                                                    | Behavior from the Report                                                                                                                                | Why This Mapping Fits                                                                                           | ATT&CK Link                                    |
| ------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Initial Access      | T1190 — Exploit Public-Facing Application                    | Attackers exploited a vulnerable internet-facing React / Next.js application using a crafted HTTP request.                                              | The attacker gained access by exploiting a public-facing web application component without authentication.      | https://attack.mitre.org/techniques/T1190/     |
| Execution           | T1059 — Command and Scripting Interpreter                    | After exploitation, attackers executed system commands on the server. Reports mention command execution involving shell commands such as curl and wget. | T1059 covers attacker use of command interpreters such as Unix shells, Windows Command Shell, or PowerShell.    | https://attack.mitre.org/techniques/T1059/     |
| Command and Control | T1105 — Ingress Tool Transfer                                | Attackers downloaded additional payloads such as scripts, backdoors, tunnelers, and miners from external infrastructure.                                | T1105 describes transferring tools or files from an external system into a compromised environment.             | https://attack.mitre.org/techniques/T1105/     |
| Persistence         | T1053.003 — Scheduled Task/Job: Cron                         | Some Linux exploitation chains created cron jobs to keep malicious payloads running.                                                                    | Cron jobs are a common Linux persistence mechanism and are directly covered by this sub-technique.              | https://attack.mitre.org/techniques/T1053/003/ |
| Persistence         | T1543.002 — Create or Modify System Process: Systemd Service | Some attacks created systemd services to maintain persistence for malicious tools.                                                                      | Creating or modifying a systemd service allows malware to restart automatically and remain active after reboot. | https://attack.mitre.org/techniques/T1543/002/ |
| Impact              | T1496 — Resource Hijacking                                   | Financially motivated actors deployed XMRig cryptocurrency miners after exploiting the vulnerability.                                                   | Cryptomining abuses victim compute resources for attacker profit, which fits Resource Hijacking.                | https://attack.mitre.org/techniques/T1496/     |

## Defensive Insights

This case shows that public-facing applications are one of the most dangerous attack surfaces because exploitation can begin within hours of disclosure. React2Shell also demonstrates why dependency management is part of cybersecurity: even if the application code is written correctly, a vulnerable framework package can expose the entire server. Effective defense requires fast patching, WAF rules as temporary mitigation, monitoring for suspicious HTTP requests, and detection of unusual server-side command execution.

## What I Learned

I learned how a single web framework vulnerability can become an initial access technique in the MITRE ATT&CK framework. I also learned that exploitation does not stop at “running a command”: attackers often follow with payload download, persistence, command-and-control, and monetization such as cryptomining. Mapping the attack to MITRE helps turn a technical vulnerability report into a defender-oriented story.

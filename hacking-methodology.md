# Hacking Methodology

{% hint style="success" %}
Hack Responsibly.

Always ensure you have **explicit** permission to access any computer system **before** using any of the techniques contained in these documents. You accept full responsibility for your actions by applying any knowledge gained here.
{% endhint %}

## [MITRE ATT\&CK](https://attack.mitre.org)

| [Initial Access](https://attack.mitre.org/tactics/TA0001) | [Execution](https://attack.mitre.org/tactics/TA0002) | [Persistence](https://attack.mitre.org/tactics/TA0003) | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) | [Defense Evasion](https://attack.mitre.org/tactics/TA0005) | [Credential Access](https://attack.mitre.org/tactics/TA0006) | [Discovery](https://attack.mitre.org/tactics/TA0007) | [Lateral Movement](https://attack.mitre.org/tactics/TA0008) | [Collection](https://attack.mitre.org/tactics/TA0009) | [Command and Control](https://attack.mitre.org/tactics/TA0011) | [Exfiltration](https://attack.mitre.org/tactics/TA0010) | [Impact](https://attack.mitre.org/tactics/TA0040) |
| --------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------- |

The hacking methodology categories align with the enterprise attack tactics in the MITRE ATT\&CK matrix. The categories are:

* **Initial access** - Gaining initial entry to the target network, usually involving password-guessing, exploits, or phishing emails
* **Execution** - Launching attacker tools and malicious code, including RATs and backdoors
* **Persistence** - Creating autostart extensibility points (ASEPs) to remain active and survive system restarts
* **Privilege escalation** - Obtaining higher permission levels for code by running it in the context of a privileged process or account
* **Defense evasion** - Avoiding security controls by, for example, turning off security apps, deleting implants, and running rootkits
* **Credential access** - Obtaining valid credentials to extend control over devices and other resources in the network
* **Discovery** - Gathering information about important devices and resources, such as administrator computers, domain controllers, and file servers
* **Lateral movement** - Moving between devices in the target network to reach critical resources or gain network persistence
* **Collection** - Locating and collecting data for exfiltration
* **Command and control** - Connecting to attacker-controlled network infrastructure to relay data or receive commands
* **Exfiltration** - Extracting data from the network to an external, attacker-controlled location

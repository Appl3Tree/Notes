---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Module 26: Trying Harder: The Challenge Labs

## PWK Challenge Lab Overview

### STOP! Do This First

_Finish all the PWK capstone exercises then finish the Assembling the Pieces module._

### Challenge Labs 0-3

_The first four labs are called **scenarios**. The goal is to gain Domain Administrator access on an Active Directory domain, and compromise as many machines on the network as possible. Some machines may not be exploitable (intended). All machines contain either a **local.txt** file, a **proof.txt** file, or both. The content of these are randomized hashes._&#x20;

#### _Challenge Lab 0: SECURA_

In the first Challenge Lab, you are tasked with performing a penetration test on SECURA's three-machine enterprise environment. This lab serves as a ramp-up before tackling the more complex Challenge Labs 1-3. You will exploit vulnerabilities in ManageEngine, pivot through internal services, and leverage insecure GPO permissions to escalate privileges and compromise the domain.

#### Challenge Lab 1: MEDTECH

You have been tasked to conduct a penetration test for MEDTECH, a recently formed IoT healthcare startup. Your objective is to find as many vulnerabilities and misconfigurations as possible in order to increase their Active Directory security posture and reduce the attack surface.

#### Challenge Lab 2: RELIA

You are tasked with a penetration test of RELIA, an industrial company building driving systems for the timber industry. The target got attacked a few weeks ago and now wants to get an assessment of their IT security. Their goal is to find out if an attacker can breach the perimeter and get Domain Admin privileges in the internal network.

#### Challenge Lab 3: SKYLARK

Skylark Industries is an aerospace multinational corporation that performs research & development on cutting-edge aviation technologies. One of their major branch offices has recently been targeted by an Advanced Persistent Threat (APT) actor ransomware attack. For this reason, the company CISO now wishes to further shield Skylark Industries' attack surface. You have been tasked to conduct a preemptive penetration test towards their HQ infrastructure and find any vulnerability that could potentially jeopardize the company's trade secrets.

{% hint style="warning" %}
Please note that Challenge 3 is significantly more difficult than Challenges 0, 1 & 2. It requires a substantial amount of pivoting, tunneling, looking for information on multiple targets and paying close attention to post-exploitation. It is _beyond_ the scope of the OSCP exam. If preparing for the exam is your main objective, you may wish to work through Challenges 4, 5 & 6 before returning Challenge 3.
{% endhint %}

### Challenge Labs 4-6

_The second type of Challenge Lab consists of an OSCP-like experience. They are composed of six OSCP machines. The intention is to provide a mock-exam experience, similar to the difficulty of the actual OSCP exam._

_Each challenge contains three machines that are connected via Active Directory, and three standalone machines that do not have any dependencies or intranet connections. All the standalone machines have a **local.txt** and a **proof.txt**._

In a sense, Challenges 4-6 provide a self-assessment of _yourself_ as much as they represent an assessment of machines and networks. We recommend that you treat them as an opportunity to discover your own strengths and weaknesses, and then to use that information to guide your next learning focus.

### Challenge Lab 7

_The third type of Challenge Lab is similar to Labs 0-3, however the complexity is significantly higher than 0-6. It requires skills/techniques beyond what was taught in this course. This is to help you transition to more advanced skills, such as those taught in PEN-300._

#### _Challenge Lab 7: ZEUS_

_The challenge is divided into three main objectives, each targeting different client systems within the Zeus.Corp domain. The first objective involves compromising a client system to find and access database configurations, and intercept authentication requests. The second objective focuses on intercepting authentication requests from another client, logging in with the captured ticket, and reading a specific document. The final objective requires participants to log in to the system, reset a user’s password, and create a backup._

_All machines contain either a **local.txt** file, a **proof.txt** file, or both. The contents of these files are randomized hashes that can be submitted to the OLP to log each compromise. Just like the Module exercise flags, the contents of these files will change on every revert of the machine._

## Challenge Lab Details

### Client-Side Simulations

Subtle hints throughout the lab help identify what the simulated client actions are. The most common interval for their actions is every three minutes.

### Machine Dependencies

Some _**machines**_ contain information required for other machines. Challenges are _**not**_ related.

### Machine Vulnerability

Every machine _does_ contain at least a **local.txt** or **proof.txt** file. This means that some machines may not have privilege escalation paths, but every machine can be accessed after obtaining Domain Administrator permissions for each of the Challenges (whether or not they are domain joined).

{% hint style="info" %}
It is important to note that the OSCP-like Challenges and the OSCP itself _DO NOT_ contain these types of machines. On the exam, every machine is designed to be exploitable, and every machine has a privilege escalation attack vector.
{% endhint %}

### Machine Ordering

IP values mean nothing. Don't read into them.

### Routers/NAT

You will need to use various techniques covered in the course to gain access to the internal networks. For example, you may need to exploit machines NAT’d behind firewalls, leveraging dual-homed hosts or client-side exploits. Lengthy attacks such as brute forcing or DOS/DDOS are highly discouraged as they will render the firewalls, along with any additional networks connected to them, inaccessible to you.

A number of machines in the labs have software firewalls enabled and may not respond to ICMP echo requests. If an IP address does not respond to ICMP echo requests, this does not necessarily mean that the target machine is down or does not exist.

### Passwords

With "regular" hardware, every intentional vector that relies on password-cracking should take less than 10 minutes with the right wordlist and parameters.

Don't waste time trying to crack passwords longer than that.

## The OSCP Exam Information

### OSCP Exam Attempt

Go to exam scheduling calendar to book the exam.

### About the OSCP Exam

The OSCP certification exam simulates a live network in a private VPN that contains a small number of vulnerable machines. The structure is exactly the same as that of Challenges 4-6. To pass, you must score 70 points. Points are awarded for low-privilege command-line shell access as well as full system compromise. The environment is completely dedicated to you for the duration of the exam, and you will have 23 hours and 45 minutes to complete it.

Once the exam has ended, you will have an additional 24 hours to put together your exam report and document your findings. You will be evaluated on the quality and content of the exam report, so please include as much detail as possible and make sure your findings are all reproducible.

### Metasploit Usage - Challenge Labs vs Exam

Metasploit is encouraged for Challenges 0-3. Be aware of metasploit restrictions for the exam though.

---
layout: post
title: "Extreme Red Team Labs Review"
date: 2026-07-15
categories:
  - Review
tags:
  - Review
  - RedTeam
  - ActiveDirectory
  - GCP
  - Azure
  - AWS
  - Cloud
keywords:
  - ""
  - ""
image: "/images/erlt/banner.png"
author: "zerofrost"
draft: false
description: ""
difficulty: Medium
showFullContent: false
---

## Extreme Red Team Labs Review

Recently I had the opportunity to go through several labs from [Extreme Red Team Labs](https://extremeredteam.0x29a.it/). The labs offer realistic, multi-layered red teaming attack chains that simulate real-world enterprise environments. The labs are designed to test not just your ability to exploit a single vulnerability, but to chain multiple techniques across different platforms and trust boundaries. 

What initially enticed me was the try-first, pay-later model. You can start the labs for free and only pay if you want the badge and certification (25 euros). It is a clever use of the foot-in-the-door technique. Once you've invested the time to complete the labs, you're much more likely to pay for the badge and certification, putting the sunk cost fallacy in play.



### Labs

The labs cover a wide range of topics requiring you to work your way through Linux machines, Active Directory domains, and cloud environments to reach the final flag. They also follow a pro labs style, where you are thrown in the deep end and left to figure out how to swim rather than being taught how to swim. There is no hand holding, nor is there any course material. It is just you, a VPN connection, and a target subnet. 

A jump box is provided but is not necessary; you can work from your own attacker machine via VPN except in a few specific scenarios where direct access to certain networks is restricted.

It is recommended to start with the AD Chains/Cloud Labs before finalizing with Summus, which is a combination of the two. However, in my case I started with Summus since it was the first lab by ERTL that I came across, after which I then proceeded with the AD Chains. Going backwards up the difficulty curve was an interesting experience. After Summus, everything else felt like a gentle downhill stroll. 

I have some experience with Active Directory. I know my way around Bloodhound, Kerberos delegations, and the usual AD abuse primitives. But when it comes to Cloud on the other hand, I am not the brightest crayon in the box. These labs force you to confront that gap regardless, which is exactly why they are valuable.

#### Summus

Summus was the most challenging lab for me and the one I learned the most from by a wide margin mainly because I did not have a lot of experience in cloud exploitation. The lab was huge. I had to compromise 12 machines across multiple domains, forests, trusts, and hybrid cloud environments. 

![](/images/erlt/summus_map.png)

The lab rewards thorough enumeration. 

Topics covered include:
- Domain enumeration and privilege escalation
- Linux and Windows exploitation and privilege escalation
- Credential extraction, abuse and replay attacks
- Exploiting authentication and MFA misconfigurations (hardcoded/default TOTP secrets)
- Exploiting domain misconfigurations (ACLs, LAPS, GMSA, delegations)
- Pivoting and lateral movement across complex on-prem and cloud environments
- Cross-forest and cross-trust attacks
- Bypassing Windows Defender and security controls
- AWS exploitation (Lambda hijacking, S3 compromise, cross-account movement)
- Azure attacks (Key Vaults, Storage Accounts, Blobs)
- GCP attacks (service accounts, instances, buckets, impersonation flaws)


If you think of the relationship between difficulty and learning as a graph, the line is directly proportional. The steeper the climb, the more you take away from it. Summus sat firmly at the top right of that curve for me. Having previously completed the MCRTA (Multi Cloud Red Team Analyst) certification helped with the cloud portions, but even then, piecing together GCP, Azure, and on-prem AD in a single chain was demanding.

![](/images/erlt/summus_badge.jpg)


#### MailService

MailService is the first of the AD Chains. It is a cross-domain AD attack chain starting from a Linux mail server. This AD Chain was a medium level lab covering the following topics:

- Linux mail server exploitation for initial access
- Network pivoting and tunneling across segmented environments
- Credential extraction from application databases
- MSSQL abuse (linked servers, command execution, privilege escalation)
- Token manipulation for privilege escalation
- Execution policy bypass and AV evasion
- Cross-forest and cross-domain authentication attacks
- Kerberos delegation attacks.
- Exploiting misconfigured domain ACLs

This lab is dense. The credential extraction from application data stores is a creative initial access vector I found interesting. The multi-domain aspect adds a layer of complexity that makes it stand out.


![](/images/erlt/mailservice_badge.jpg)


#### Calipendula

Calipendula blends GCP cloud attacks with on-prem Active Directory exploitation. The lab does a great job blending cloud and on-prem AD attack paths.It covers the following topics:

- GCP cloud exploitation (IAM, Cloud Run & Secret Exploitation)
- NTLM relay attacks.
- Kerberos Delegation attacks.
- LAPS and GMSA abuse
- Exploiting misconfigured domain ACLs
- Network tunneling and proxying.
- Service account impersonation and OAuth token abuse.
- Windows Defender and AMSI evasion

The cloud enumeration portion is particularly realistic and mirrors real-world assessments. For someone like me who finds cloud tricky, this lab was a good challenge covering GCP.

#### Ifixtcentcen

Ifixtcentcen covers Kerberos attacks across Windows and Linux. Topics include:

- Cross-platform Kerberos attacks (Windows and Linux)
- Kerberos constrained delegation exploitation
- Windows Defender and AMSI evasion
- PPL (Protected Process Light) bypass
- Exploiting misconfigured domain ACLs
- Credential Guard bypass
- ASREP-roasting and Kerberos pre-authentication attacks
- Token manipulation and impersonation
- Binary reverse engineering.

The defense bypass sections are particularly well done. What makes this lab stand out is the cross-platform Kerberos angle which is a scenario you rarely see. 

![](/images/erlt/ifix_badge.jpg)


### Pros & Cons
I generally liked the labs and I would recommend them to anyone interested in red team/cloud exploitation. These were the things I liked about the labs:

- Realistic scenarios:  The labs mirror real enterprise environments with multi-domain trusts, cloud integrations, and proper security controls.
- Diverse techniques: You get exposure to on-prem AD, cloud, Linux pivoting, database abuse, and Kerberos attacks all in one lab.
- No hand-holding: The labs provide minimal guidance, forcing you to enumerate thoroughly, research and think critically.
- Staff support: If you are truly stuck, the staff can provide hints to point you in the right direction without giving away the answer.
- Good difficulty curve: The labs range from Medium to Hard, giving a solid learning progression.


Even though the labs were solid, there are some things I did not like about them that leave room for improvement. Below are some of the issues encountered.

- Shared instance pollution: The labs run on a shared infrastructure, meaning other players' files, tools, and credentials can remain in the environment, which is both annoying and spoiling. Considering the price, this is not a major issue. 

- No reset mechanism: There is no easy way to reset the lab state if something breaks or if the environment gets polluted. Resets also require three votes from players which can be difficult to coordinate, especially in off-peak hours. 

### Should you Try the Labs?

Absolutely! Extreme Red Team Labs offer some of the most realistic red teaming challenges I have encountered. The integration of cloud platforms alongside traditional AD attacks is a standout feature and reflects how modern enterprise environments actually look. The labs are well designed and will push your skills. 

Although I completed the labs without using a C2, I highly recommend it as an excellent playground for testing C2 pivoting and operational capabilities with frameworks such as Havoc, Adaptix, Mythic, Cobalt Strike, etc. 

I would recommend these labs to anyone interested in red team/cloud stuff. If you are preparing for certifications like CRTO or CRTE, or just want to level up your red teaming/cloud game, these labs are worth the time.



### References
A good friend of mine has written individual reviews for the AD chains which you can find below.

* [Mail Service Review](https://sploitony.com/blog/extreme-red-team-mailservice.html)
* [Calipendula Review](https://sploitony.com/blog/extreme-red-team-lab-calipendula.html)

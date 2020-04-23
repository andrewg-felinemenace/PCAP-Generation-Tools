#!/usr/bin/python

from scapy.all import *

import random

import gzip
import zlib
import StringIO

import os

def randtext(min=3, max=12):
	#chars = range(0x41, 0x5a) + range(0x61, 0x7a) + range(0x30, 0x39)
	#since I am seeing below error, changed to different representaton
	#TypeError: unsupported operand type(s) for +: 'xrange' and 'xrange'
	chars = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, \
		63, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89]
	while(max > len(chars)):
		chars += chars

	#if(max > len(chars)):
	#	max = len(chars)

	text = random.sample(chars, random.randint(min, max))
	n = ''.join([ chr(t) for t in text ])
	return n

class Host:
	"""
	Host is a class to indicate settings for a host. It has the ether and ip parameters. This is just to
	keep things tidy
	"""

	#avail = range(0x41, 0x5a) + range(0x61, 0x7a) + range(0x30, 0x39)
	avail = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, \
		63, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89]
	# ascii bytes. sometimes we can generate amusing strings in pcap file :)

	def __init__(self):
		self.ether = '00:{0:x}:{1:x}:{2:x}:{3:x}:{4:x}'.format(*random.sample(self.avail, 5))
		self.ip = '{0}.{1}.{2}.{3}'.format(*random.sample(self.avail, 4))

	def __repr__(self):
		return "<Host ether='{0}' ip='{1}'>".format(self.ether, self.ip)

class PCAP:
	"""
	PCAP class
	"""

	def __init__(self, filename):
		self.filename = filename			# Where we will write the packets
		self.client = Host()				# Information for the 'client'
		self.server = Host()				# Information for the 'server'
		self.packets = []				# List of packets to be written out
		self.closed = False

	def __del__(self):
		self.close()

	def close(self):
		"""close() writes the packets to disk"""
		if(len(self.packets)):
			wrpcap(self.filename, self.packets)

		self.closed = True

	def add_packet(self, pkt):
		"""add_packet(pkt) appends to the packets list. This mechanism should probably be replaced with something that
		writes to disk immediately, as opposed to buffering in memory."""
		assert(self.closed == False)

		self.packets.append(pkt)

	def tcp_conn_to_client(self, dport, sport = 0):
		"""tcp_conn_to_client returns a TCPConn() object, where TCP streams come from self.server and go to self.client.
		This is useful when the server has to connect to the client, like in certain protocols (FTP active mode).
		"""
		assert(self.closed == False)

		if(sport == 0):
			sport = random.randint(49152, 65535)

		return TCPConn(self, self.client, self.server, dport, sport)

	def tcp_conn_to_server(self, dport, sport = 0):
		"""tcp_conn_to_server returns a TCPConn() object, where TCP streams come from self.client and go to self.server"""
		assert(self.closed == False)

		if(sport == 0):
			sport = random.randint(49152, 65535)

		return TCPConn(self, self.server, self.client, dport, sport)

class TCPConn:
	def __init__(self, pcap, server, client, dport, sport):
		self.pcap = pcap
		self.closed = False

		# not too large that we have to deal with negative numbers ;D
		self.cli_seq = random.randint(0, 0x2fffffff)
		self.srv_seq = random.randint(0, 0x2fffffff)

		self.server = server
		self.client = client
		self.dport = dport
		self.sport = sport

		self.to_server_pkt = Ether(dst=self.server.ether, src=self.client.ether) / IP(dst=self.server.ip, src=self.client.ip)
		self.to_client_pkt = Ether(dst=self.client.ether, src=self.server.ether) / IP(dst=self.client.ip, src=self.server.ip)

		self.do_handshake()


	def do_handshake(self):
		assert(self.closed == False)
		# write SYN packet from client to server, sport -> dport

		pkt = self.to_server_pkt / TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.cli_seq)
		self.pcap.add_packet(pkt)
		self.cli_seq += 1

		# write SYN|ACK packet from server -> client

		pkt = self.to_client_pkt / TCP(sport=self.dport, dport=self.sport, flags="SA", seq=self.srv_seq, ack=self.cli_seq)
		self.pcap.add_packet(pkt)
		self.srv_seq += 1

		# write ACK packet from client -> server

		pkt = self.to_server_pkt / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.cli_seq, ack=self.srv_seq)
		self.pcap.add_packet(pkt)

	def finish(self):
		assert(self.closed == False)
		# write server -> client FIN|ACK
		pkt = self.to_client_pkt / TCP(sport=self.dport, dport=self.sport, flags = "FA", seq=self.srv_seq, ack=self.cli_seq)
		self.pcap.add_packet(pkt)
		self.srv_seq += 1

		# write client -> server ACK
		pkt = self.to_server_pkt / TCP(sport=self.sport, dport=self.dport, flags = "A", seq=self.cli_seq, ack=self.srv_seq)
		self.pcap.add_packet(pkt)

		# write client -> server FIN|ACK
		pkt = self.to_server_pkt / TCP(sport=self.sport, dport=self.dport, flags = "FA", seq=self.cli_seq, ack=self.srv_seq)
		self.pcap.add_packet(pkt)
		self.cli_seq += 1

		# write server -> client ACK
		pkt = self.to_server_pkt / TCP(sport=self.dport, dport=self.sport, flags="A", seq=self.srv_seq, ack = self.cli_seq)
		self.pcap.add_packet(pkt)

		self.closed = True

	def to_client(self, data):
		assert(self.closed == False)

		for offset in range(0, len(data), 1200):
			piece = data[offset:offset+1200]

			pkt = self.to_client_pkt / TCP(sport=self.dport, dport=self.sport, flags="PA", seq=self.srv_seq, ack=self.cli_seq) / piece
			self.pcap.add_packet(pkt)
			self.srv_seq += len(piece)

			pkt = self.to_server_pkt / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.cli_seq, ack=self.srv_seq)
			self.pcap.add_packet(pkt)

	def to_server(self, data):
		assert(self.closed == False)

		for offset in range(0, len(data), 1200):
			piece = data[offset:offset+1200]

			pkt = self.to_server_pkt / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.cli_seq, ack=self.srv_seq) / piece
			self.pcap.add_packet(pkt)
			self.cli_seq += len(piece)

			pkt = self.to_client_pkt / TCP(sport=self.dport, dport=self.sport, flags="A", seq=self.srv_seq, ack=self.cli_seq)
			self.pcap.add_packet(pkt)

class FileObj:
	def __init__(self, filename):
		self.filename = os.path.basename(filename)
		self.dirname = os.path.dirname(os.path.abspath(filename))
		self.filedata = open(filename, 'rb').read()

	def get_raw(self, prefix=""):
		return prefix + self.filedata

	def get_gzip(self, prefix=""):
		s = StringIO.StringIO()
		g = gzip.GzipFile(randtext(), 'w', random.randint(1, 9), s)
		g.write(prefix + self.filedata)
		g.close()

		return s.getvalue()

	def get_zlib(self,prefix=""):
		return zlib.compress(prefix+self.filedata, random.randint(1, 9))

	def get_deflate(self, prefix=""):
		return self.get_zlib(prefix)

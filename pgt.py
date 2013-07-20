#!/usr/bin/python

"""
pgt stands for pcap generation tool, which generates pcaps of files being
transferred across the network, using a variety of (plaintext) protocols.

at the moment, it implements smtp, imap, http, ftp, and pop3.
"""

import random
from pgtlib import *

import magic

from optparse import OptionParser

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

class HTTP:
	get_request = (
		"GET /{0} HTTP/1.1\r\n"
		"Host: {host}\r\n"
		"Accept-Encoding: gzip,compress,deflate\r\n"
		"Keep-Alive: 300\r\n"
		"Connection: keep-alive\r\n"
		"\r\n"
	)

	get_response = (
		"HTTP/1.1 200 Ok\r\n"
		"{content_type}"
		"{content_encoding}"
		"{transfer_encoding}"
		"Server: Apache/2.0\r\n"
		"{content_length}"
		"\r\n"
	)

	post_request = (
		"POST /{0} HTTP/1.1\r\n"
		"Host: {host}\r\n"
		"Accept-Encoding: gzip,deflate,compress\r\n"
		"Keep-Alive: 300\r\n"
		"Connection: keep-alive\r\n"
		"{content_type}"
		"{content_encoding}"
		"{transfer_encoding}"
		"{content_length}"
		"\r\n"
		"{1}"
	)

	post_response = (
		"HTTP/1.1 200 Ok\r\n"
		"Content-Type: text/html\r\n"
		"Connection: close\r\n"
		"Content-Length: {content_length}\r\n"
		"\r\n"
		"{content}\r\n"
	)

	def set_options(self, options):
		self.http_port = options.http_port
		if options.uri:
			self.uri = options.uri
		else:
			self.uri = randtext()

	def make_pcap(self, pcap, req, resp):
		stream = pcap.tcp_conn_to_server(self.http_port)
		
		# Write client request
		stream.to_server(req)
		# Write server response
		stream.to_client(resp)

		stream.finish()

	def chunkify(self, data):
		offset = 0
		ret = []

		max_size = (len(data) / 8) + 2


		while offset < len(data):
			count = random.randint(1, max_size)
			piece = data[offset:offset+count]

			chunk = "{0:x}\r\n{1}\r\n".format(len(piece), piece)
			ret.append(chunk)
			
			offset += len(piece)
			
		ret.append("0\r\n\r\n")

		return ''.join(ret)

	def make_content_length(self, data):
		return "Content-Length: {0}\r\n".format(len(data))

	def make_GET_pcap(self, pcapname, fileobj, content_encoding, transfer_encoding, content_type):
		ce = ""					# Content Encoding
		te = ""					# Transfer Encoding
		cl = ""					# Content-Length
		ct = ""					# Content Type

		fp = getattr(fileobj, 'get_{0}'.format(content_encoding))
		data = fp()

		if(content_encoding != 'raw'):
			ce = "Content-Encoding: {0}\r\n".format(content_encoding)

		if(transfer_encoding != 'raw'):
			assert(transfer_encoding == "chunked")
			te = "Transfer-Encoding: {0}\r\n".format(transfer_encoding)
			data = self.chunkify(data)
		else:
			cl = self.make_content_length(data)

		ct = "Content-Type: {0}\r\n".format(content_type)

		resp = self.get_response.format(content_encoding=ce, transfer_encoding=te, content_length=cl, content_type=ct)
		resp += data

		pcap = PCAP(pcapname)
		req = self.get_request.format(self.uri, host=pcap.server.ip)
		self.make_pcap(pcap, req, resp)
		pcap.close()

	def make_POST_pcap(self, pcapname, fileobj, content_encoding, transfer_encoding, content_type):
		ce = ""
		te = ""
		cl = ""
		ct = ""

		prefix = randtext() + "="

		fp = getattr(fileobj, 'get_{0}'.format(content_encoding))
		data = fp(prefix=prefix)

		if(content_encoding != 'raw'):
			ce = "Content-Encoding: {0}\r\n".format(content_encoding)
		
		if(transfer_encoding != 'raw'):
			assert(transfer_encoding == "chunked")
			te = "Transfer-Encoding: {0}\r\n".format(transfer_encoding)
			data = self.chunkify(data)
		else:
			cl = self.make_content_length(data)

		ct = "Content-Type: {0}\r\n".format(content_type)

		pcap = PCAP(pcapname)
		req = self.post_request.format(self.uri, data, host=pcap.server.ip, content_encoding=ce, transfer_encoding=te, content_length=cl, content_type=ct)

		content = randtext(max=64)
		resp = self.post_response.format(content=content, content_length=len(content))
		self.make_pcap(pcap, req, resp)
		pcap.close()


	def run(self, fileobj):
		mimetype = magic.Magic(mime=True)
		contenttype = mimetype.from_file(fileobj.dirname+'/'+fileobj.filename)

		for method in [ 'GET', 'POST' ]:
			for encoding in [ 'raw', 'gzip', 'deflate' ]:
				for transfer in [ 'raw', 'chunked' ]:
					pcapname = 'output/{0}/HTTP_{1}_{2}_{3}.pcap'.format(fileobj.filename, method, encoding, transfer)
					print "[*] {0} ...".format(pcapname)
					fp = getattr(self, 'make_{0}_pcap'.format(method))
					fp(pcapname, fileobj, encoding, transfer, contenttype)



class Email:
	"""
	The Email() class is responsible for SMTP, POP3 and IMAP, considering the similiarities between them
	"""

	def set_options(self, options):
		self.pop3_port = options.pop3_port
		self.imap_port = options.imap_port
		self.smtp_port = options.smtp_port

	def make_POP3_pcap(self, pcapname, email):
		pcap = PCAP(pcapname)
		conn = pcap.tcp_conn_to_server(self.pop3_port)

		conn.to_client("+OK Microsoft Exchange Server 2003 POP3 server version 6.5.7638.1 ({0}.{1}.com) ready\r\n".format(randtext(), randtext()))
		conn.to_server("USER {0}\r\n".format(randtext()))
		conn.to_client("+OK\r\n")
		conn.to_server("PASS {0}\r\n".format(randtext()))
		conn.to_client("+OK\r\n")
		conn.to_server("RETR {0}\r\n".format(random.randint(1, 32)))
		conn.to_client("+OK {0} octets\r\n{1}\r\n.\r\n".format(len(email), email))
		conn.to_server("QUIT\r\n")
		conn.to_client("+OK\r\n")

		conn.finish()
		pcap.close()

	def make_IMAP_pcap(self, pcapname, email):
		pcap = PCAP(pcapname)
		conn = pcap.tcp_conn_to_server(self.imap_port)
		
		# Banner + login
		tag = randtext()
		conn.to_client("* OK Microsoft Exchange Server 2003 IMAP4rev1 server version 6.5.7638.1 ({0}.{1}.com) ready.\r\n".format(randtext(), randtext()))
		conn.to_server("{0} LOGIN {1}@{2}.com {3}\r\n".format(tag, randtext(), randtext(), randtext()))
		conn.to_client("{0} OK User logged in\r\n".format(tag))

		# Handle select
		tag = randtext()
		conn.to_server("{0} SELECT INBOX\r\n".format(tag))
		conn.to_client("* FLAGS (\Answered \Flagged \Deleted \Seen \Draft NonJunk Junk followup $label1 $label2 $label3 $label4 $label5 meetings $Forwarded $MDNSent $has_cal)\r\n")
		conn.to_client("* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft NonJunk Junk followup $label1 $label2 $label3 $label4 $label5 meetings $Forwarded $MDNSent $has_cal \*)] Flags permitted.\r\n")
		conn.to_client("* {0} EXISTS\r\n".format(random.randint(1, 5000)))
		conn.to_client("* 0 RECENT\r\n")
		conn.to_client("* OK [UIDVALIDITY 1229221773] UIDs valid\r\n")
		conn.to_client("* OK [UIDNEXT {0}] Predicted next UID\r\n".format(random.randint(5000, 6000)))
		conn.to_client("* OK [HIGHESTMODSEQ {0}] Highest\r\n".format(random.randint(5000, 6000)))
		conn.to_client("{0} OK [READ-WRITE] Select completed.\r\n".format(tag))

		# Fetch email
		tag = randtext()
		conn.to_server("{0} FETCH {1} rfc822\r\n".format(tag, random.randint(1, 100)))
		conn.to_client("* 1 FETCH (RFC822 {{{0}}}\r\n{1}\r\n)\r\n{2} OK Fetch completed\r\n".format(len(email), email, tag))

		# Quit from the server
		tag = randtext()
		conn.to_server("{0} LOGOUT\r\n".format(tag))
		conn.to_client("{0} OK Logout completed.\r\n".format(tag))
		
		conn.finish()
		pcap.close()

	def make_SMTP_pcap(self, pcapname, email):
		pcap = PCAP(pcapname)
		conn = pcap.tcp_conn_to_server(self.smtp_port)
		
		host = "{0}.{1}.com".format(randtext(), randtext())

		day = random.choice(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
		mon = random.choice(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Oct", "Sep", "November", "December"])
		banner = "220 {0} Microsoft ESMTP MAIL Service, Version: 6.0.3790.3959 ready at  {1}, {2:02} {3} 2010 {4:02}:{5:02}:{6:02} {7}{8:02}00\r\n"
		banner = banner.format(host, day, random.randint(1, 30), mon, random.randint(1, 31), random.randint(0, 12), random.randint(0, 60), random.choice(["-", "+"]), random.randint(1, 11))

		conn.to_client(banner)
		conn.to_server("EHLO {0}\r\n".format(randtext()))
		
		conn.to_client("250-{0}.{1}.com Hello [10.{2}.{3}.{4}]\r\n".format(randtext(), randtext(), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))
		conn.to_client("250-XXXA\r\n250-SIZE\r\n250-ETRN\r\n250-PIPELINING\r\n250-DSN\r\n250-ENHANCEDSTATUSCODES\r\n250-8bitmime\r\n250-BINARYMIME\r\n250-XXXXXXXB\r\n250-XXXC\r\n250-XXXXXXXXXXXXXXXXXXXXXXXD\r\n250-XXXXXXXXXXXE\r\n250-AUTH GSSAPI NTLM LOGIN\r\n250-XXXXXXXXXF\r\n250-XXXXXXXXXXXG\r\n250-XXXXXXH\r\n250 XI\r\n")
		
		rcpt = "{0}@{1}.com".format(randtext(), randtext())
		mfrm = "{0}@{1}.com".format(randtext(), randtext())

		conn.to_server("MAIL FROM: <{0}>\r\n".format(mfrm))
		conn.to_client("250 2.1.0 {0}....Sender OK\r\n".format(mfrm))
		conn.to_server("RCPT TO: <{0}>\r\n".format(rcpt))
		conn.to_client("250 2.1.5 {0}\r\n".format(rcpt))

		conn.to_server("DATA\r\n")
		conn.to_client("354 Start mail input; end with <CRLF>.<CRLF>\r\n")
		conn.to_server("{0}\r\n.\r\n".format(email))

		conn.to_client("250 2.6.0 <{0}-{1}@{2}> Queued mail for delivery\r\n".format(randtext().upper(), randtext(max=19), host))
		conn.to_server("QUIT\r\n")


		conn.finish()
		pcap.close()

	def make_mail(self, fileobj, encoder):
		base = MIMEMultipart()

		base['From'] = "{0}@{1}.com".format(randtext(), randtext())
		base['To'] = "{0}@{1}.com".format(randtext(), randtext())
		base['Subject'] = "{0} {1} {2} {3}".format(randtext(), randtext(), randtext(), randtext())

		mimetype = magic.Magic(mime=True)
		contenttype = mimetype.from_file(fileobj.dirname+'/'+fileobj.filename).split('/')
		msg = MIMEBase(contenttype[0], contenttype[1])

		msg.set_payload(fileobj.get_raw())
		msg.add_header('Content-Disposition', 'attachment', filename=randtext())

		fp = getattr(encoders, 'encode_{0}'.format(encoder))
		fp(msg)

		base.attach(msg)

		return base.as_string()	

	def run(self, fileobj):
		# seems there is a gzip first, base64 encode option which would be good to include
		# however, that's non standard. I'll add it in later on.

		encoders = [ 'base64', '7or8bit', 'quopri' ]
		protocols = [ 'POP3', 'IMAP', 'SMTP' ]

		pcapname = "output/{0}/{{0}}_{{1}}.pcap".format(fileobj.filename)

		for protocol in protocols:
			for encoder in encoders:
				msg = self.make_mail(fileobj, encoder)
				pn = pcapname.format(protocol, encoder)
				print "[*] {0}...".format(pn)
				fp = getattr(self, 'make_{0}_pcap'.format(protocol))
				fp(pn, msg)
			

class FTP:
	"""
	FTP creates pcaps for active and passive ftp connections, both upload and download.
	"""

	def set_options(self, options):
		self.ftp_port = options.ftp_port

	def make_FTP_pcap(self, pcapname, fileobj, upload, active):
		print "[*] {0}...".format(pcapname)

		pcap = PCAP(pcapname)
		conn = pcap.tcp_conn_to_server(self.ftp_port)

		conn.to_client("220 {0}.{1}.com FTP Server ready.\r\n".format(randtext(), randtext()))

		user = randtext()
		conn.to_server("USER {0}\r\n".format(user))
		conn.to_client("331 Please provide your password\r\n")
		conn.to_server("PASS {0}\r\n".format(randtext()))
		conn.to_client("230 User {0} logged in\r\n".format(user))

		port = random.randint(1024, 65535)

		if(active):
			conn.to_server("PORT {0},{1},{2}\r\n".format(pcap.client.ip.replace(".", ","), port/256, port % 256))
			conn.to_client("200 PORT command successful.\r\n")
			data_conn = pcap.tcp_conn_to_client(port, 20)
		else:
			conn.to_server("PASV\r\n")
			conn.to_client("227 Entering Passive Mode ({0},{1},{2}).\r\n".format(pcap.server.ip.replace(".", ","), port/256, port %256))
			data_conn = pcap.tcp_conn_to_server(port)

		filename = randtext()
		if(upload):
			conn.to_server("STOR {0}\r\n".format(filename))
			conn.to_client("150 FILE: {0}\r\n".format(filename))

			if(active):
				# Storing a file, means data needs to come from
				# client, to server. In active mode, that means 
				# to client.
				data_conn.to_client(fileobj.get_raw())
			else:
				# Storing a file in passive mode, means the data
				# needs to come from client, to server.
				data_conn.to_server(fileobj.get_raw())

		else:
			conn.to_server("RETR {0}\r\n".format(filename))
			conn.to_client("150 Transfer in progress\r\n")
			if(active):
				# Getting contents from a file in active mode means that it comes from
				# server, to client. Since active ftp switches things around, that means to
				# server
				data_conn.to_server(fileobj.get_raw())
			else:
				# and switch it to normal mode for passive ocnnections
				data_conn.to_client(fileobj.get_raw())

		data_conn.finish()
		conn.to_client("226 Transfer complete.\r\n")
		conn.to_server("QUIT\r\n")
		conn.to_client("221 Goodbye.\r\n")
		conn.finish()
		pcap.close()

	def run(self, fileobj):
		pcapname = "output/{0}/FTP_{{0}}_{{1}}.pcap".format(fileobj.filename)

		self.make_FTP_pcap(pcapname.format("upload", "active"), fileobj, True, True)
		self.make_FTP_pcap(pcapname.format("upload", "passive"), fileobj, True, False)
		self.make_FTP_pcap(pcapname.format("download", "active"), fileobj, False, True)
		self.make_FTP_pcap(pcapname.format("download", "passive"), fileobj, False, False)


def parse_args(args):
	parser = OptionParser(usage="Usage: %prog [options] [filenames]")
	parser.add_option("--http-port", type="int", default=80, help="Port number for HTTP connections [default: %default]", metavar="PORT")
	parser.add_option("--ftp-port", type="int", default=21, help="Port number for FTP connections [default: %default]", metavar="PORT")
	parser.add_option("--imap-port", type="int", default=143, help="Port number for IMAP connections [default: %default]", metavar="PORT")
	parser.add_option("--smtp-port", type="int", default=25, help="Port number for SMTP connections [default: %default]", metavar="PORT")
	parser.add_option("--pop3-port", type="int", default=110, help="Port number for POP3 connections [default: %default]", metavar="PORT")
	parser.add_option("-u","--uri",default=None,help="Specify a URI to download",metavar="URI")

	return parser.parse_args(args)				


if __name__ == '__main__':
	protocols = [ FTP(), Email(), HTTP() ]

	opts, args = parse_args(sys.argv[1:])
	for file in args:
		fo = FileObj(file)

		try:
			os.mkdir('output/{0}'.format(fo.filename))
		except OSError:
			pass

		for proto in protocols:
			print "[*] Doing {0}".format(proto.__class__.__name__)
			proto.set_options(opts)
			proto.run(fo)


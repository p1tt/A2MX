#!/usr/bin/env python3

import sys
import socket
import select
import struct
import os

from ecc import ECC

class InvalidDataException(Exception):
	pass

class A2MXServer():
	def __init__(self, nodelist):
		self.nodelist = nodelist

		bind = ('', 0xA22)

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setblocking(0)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		while True:
			try:
				self.sock.bind(bind)
				break
			except OSError:
				bind = (bind[0], bind[1] + 1)
		print("bound to", bind)
		self.sock.listen(5)
		self.nodelist.add(self)

	def fileno(self):
		return self.sock.fileno()

	def select_r(self):
		sock, addr = self.sock.accept()
		A2MXStream(self.nodelist, sock=sock)

	def select_w(self):
		assert False
	def select_e(self):
		assert False

	def finish(self):
		self.sock.close()
		self.nodelist.remove(self)

def A2MXRequest(fn):
	fn.A2MXRequest__marker__ = True
	return fn

class A2MXStream():
	def __init__(self, nodelist=None, uri=None, sock=None):
		assert nodelist != None
		assert (uri == None and sock != None) or (uri != None and sock == None)
		self.nodelist = nodelist
		self.uri = uri
		self.__connected = False
		self.__remote_ecc = None
		self.__remote_auth = False
		self.__pub_sent = False
		if sock:
			self.sock = sock
			self.sock.setblocking(0)
			self.connected()
		elif uri != None:
			assert uri.startswith('ax://')
			self.uri = uri
			hostport = uri[5:].split(':')
			assert len(hostport) >= 1
			host = hostport[0]
			if len(hostport) == 1:
				port = 0xA22
			elif len(hostport) == 2:
				port = int(hostport[1])
			else:
				assert False

			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.setblocking(0)
			try:
				self.sock.connect((host, port))
			except BlockingIOError as e:
				if e.errno != 115:
					raise
			self.nodelist.wadd(self)

	def fileno(self):
		return self.sock.fileno()

	def select_r(self):
		try:
			data = self.sock.recv(4096)
		except ConnectionResetError:
			data = False
		if not data:
			self.finish()
			return
		self.data += data
		while len(self.data) >= self.handler[0]:
			self.handler[1](self.handler[0])

	def select_w(self):
		if not self.__connected:
			self.nodelist.wremove(self)
			self.connected()
		else:
			assert False

	def select_e(self):
		print("select_e")
		self.finish()

	def connected(self):
		self.__connected = True
		self.data = bytearray()
		self.handler = (4, self.getlength)
		self.nodelist.add(self)
		if self.uri != None:
			self.__send_pub()

	def __send_pub(self):
		ecc = self.nodelist.ecc
		x, ybit = ecc.point_compress(ecc.pubkey_x, ecc.pubkey_y)
		self.send(b'A', b'X' if ybit else b'x', x)
		self.__pub_sent = True

	def getlength(self, length):
		assert len(self.data) >= 4
		length = struct.unpack_from('>L', self.data[:4])[0]
		del self.data[:4]
		self.handler = (length, self.getdata)

	def getdata(self, length):
		assert len(self.data) >= length
		data = self.data[:length]
		del self.data[:length]

		if self.__pub_sent:		# if we sent our public key then all data we receive has to be encrypted
			data = self.nodelist.ecc.decrypt(bytes(data))

		if self.__remote_ecc == None:	# first data we expect is the compressed remote public key
			if chr(data[0]) != 'A':
				raise InvalidDataException('1')
			if chr(data[1]) == 'X':
				ybit = 1
			elif chr(data[1]) == 'x':
				ybit = 0
			else:
				raise InvalidDataException('2')
			pubkey_x, pubkey_y = self.nodelist.ecc.point_uncompress(bytes(data[2:]), ybit)

			self.__remote_ecc = ECC(pubkey_x=pubkey_x, pubkey_y=pubkey_y)
			# ok we have the remote public key, from now on we send everything encrypted
			self.__raw_send = self.send
			self.send = self.encrypted_send

			if not self.__pub_sent:	# send our public key if we haven't already
				self.__send_pub()

			self.send(self.nodelist.ecc.sign(self.__remote_ecc.get_pubkey()))
		elif not self.__remote_auth:	# second data is our own public key signed by remote
			auth = self.__remote_ecc.verify(bytes(data), self.nodelist.ecc.get_pubkey())
			if not auth:
				raise InvalidDataException('3')
			self.__remote_auth = True
			print("connection up with", self.__remote_ecc.get_pubkey())
			if self.uri != None:
				d = self.request('pullNetworkInfo', 'adsf')
				d += self.request('parse')
				d += self.request('shit', '0123456789')
				self.send(d)
		else:
			self.parse(data)
		self.handler = (4, self.getlength)

	def parse(self, data):
		i = 0
		while i < len(data):
			requestLen = struct.unpack('>L', data[i:i+4])[0]
			i += 4
			ri = i
			args = []
			while ri < i + requestLen:
				argLen = struct.unpack('>L', data[ri:ri+4])[0]
				ri += 4
				arg = data[ri:ri+argLen]
				ri += argLen
				args.append(arg)
			i = ri
			fn = args[0].decode('UTF-8')
			try:
				f = getattr(self, fn)
			except AttributeError:
				pass
			else:
				try:
					if f.A2MXRequest__marker__ == True:
						f(*args[1:])
						continue
				except AttributeError:
					pass
			print("Invalid request {}".format(fn))
		assert i == len(data)

	def request(self, *args):
		data = b''
		for arg in args:
			if isinstance(arg, str):
				arg = arg.encode('UTF-8')
			data += struct.pack('>L', len(arg))
			data += arg
		return struct.pack('>L', len(data)) + data

	def send(self, *data):
		length = 0
		sdata = []
		for d in data:
			length += len(d)
		self.sock.send(struct.pack('>L', length), socket.MSG_MORE)
		for d in data[:-1]:
			self.sock.send(d, socket.MSG_MORE)
		self.sock.send(data[-1])

	def encrypted_send(self, *data):
		data = b''.join(data)
		data = self.nodelist.ecc.encrypt(data, self.__remote_ecc.get_pubkey())
		self.__raw_send(data)

	def finish(self):
		print("finish")
		self.sock.close()
		self.nodelist.remove(self)

	@A2MXRequest
	def pullNetworkInfo(self, time):
		print("pullNetworkInfo", time)

class A2MXNodelist():
	def __init__(self):
		self.rlist = []
		self.wlist = []
		try:
			with open('.a2mx/priv', 'rb') as f:
				privkey = f.read()
			with open('.a2mx/pub', 'rb') as f:
				pubkey = f.read()
		except FileNotFoundError:
			privkey = None
			pubkey = None
		self.ecc = ECC(privkey=privkey, pubkey=pubkey)
		if privkey == None:
			os.umask(63)	# 0700
			try:
				os.mkdir('.a2mx')
			except FileExistsError:
				pass
			with open('.a2mx/priv', 'wb') as f:
				f.write(self.ecc.get_privkey())
			with open('.a2mx/pub', 'wb') as f:
				f.write(self.ecc.get_pubkey())
	def add(self, selectable):
		self.rlist.append(selectable)
	def remove(self, selectable):
		self.rlist.remove(selectable)
	def wadd(self, selectable):
		self.wlist.append(selectable)
	def wremove(self, selectable):
		self.wlist.remove(selectable)
	def select(self):
		r, w, e = select.select(self.rlist, self.wlist, self.rlist)
		for sock in e:
			sock.select_e()
		for sock in w:
			sock.select_w()
		for sock in r:
			sock.select_r()
	def shutdown(self):
		for sock in set(self.rlist + self.wlist):
			sock.finish()

nodelist = A2MXNodelist()
server = A2MXServer(nodelist)

for uri in sys.argv[1:]:
	print("connect to", uri)
	c = A2MXStream(nodelist, uri=uri)

try:
	while True:
		nodelist.select()
except KeyboardInterrupt:
	nodelist.shutdown()


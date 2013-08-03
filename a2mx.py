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
		print("I am", ECC.b58(self.nodelist.ecc.pubkey_hash()).decode('ascii'), "bound to", bind)
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
		self.remote_ecc = None
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
		self.send(ecc.pubkey_c())
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

		if self.remote_ecc == None:	# first data we expect is the compressed remote public key
			pubkey_x, pubkey_y = self.nodelist.ecc.key_uncompress(data)
			self.remote_ecc = ECC(pubkey_x=pubkey_x, pubkey_y=pubkey_y)

			# ok we have the remote public key, from now on we send everything encrypted
			self.__raw_send = self.send
			self.send = self.encrypted_send

			if not self.__pub_sent:	# send our public key if we haven't already
				self.__send_pub()

			# send the remote public key signed by us
			self.send(self.nodelist.ecc.sign(self.remote_ecc.get_pubkey()))
		elif not self.__remote_auth:	# second data is our own public key signed by remote
			auth = self.remote_ecc.verify(bytes(data), self.nodelist.ecc.get_pubkey())
			if not auth:
				raise InvalidDataException('3')
			self.__remote_auth = True
			print("connection up with", ECC.b58(self.remote_ecc.pubkey_hash()).decode('ascii'))

			# inform the peer about us
			ecc = self.nodelist.ecc
			data = bytearray()
			data += ecc.pubkey_c()
			data += self.remote_ecc.pubkey_c()
			data = bytes(data)
			r = self.request(b'I', ecc.pubkey_c(), self.remote_ecc.pubkey_c(), ecc.sign(data))
			self.send(r)
		else:
			for d in self.parse(data):
				fn = d[0].decode('UTF-8')
				try:
					f = getattr(self, fn)
				except AttributeError:
					pass
				else:
					if hasattr(f, 'A2MXRequest__marker__') and f.A2MXRequest__marker__ == True:
						f(*d[1:])
						continue
				print("Invalid request {}".format(fn))
		self.handler = (4, self.getlength)

	@staticmethod
	def parse(data):
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
			yield args
		assert i == len(data)

	@staticmethod
	def request(*args):
		data = b''
		for arg in args:
			if isinstance(arg, str):
				arg = arg.encode('UTF-8')
			data += struct.pack('>L', len(arg))
			data += arg
		return struct.pack('>L', len(data)) + data

	def send(self, *data):
		length = 0
		for d in data:
			length += len(d)
		self.sock.send(struct.pack('>L', length), socket.MSG_MORE)
		for d in data[:-1]:
			self.sock.send(d, socket.MSG_MORE)
		self.sock.send(data[-1])

	def encrypted_send(self, *data):
		data = b''.join(data)
		data = self.nodelist.ecc.encrypt(data, self.remote_ecc.get_pubkey())
		self.__raw_send(data)

	def finish(self):
		print("finish")
		self.sock.close()
		self.nodelist.remove(self)

	@A2MXRequest
	def I(self, path, mypub, signature):
		self.nodelist.new_path(path, mypub, signature, self)

class A2MXPath():
	def __init__(self, path, pub, signature):
		self.endnode = False
		self.nextpath = False

		self.pub = ECC()
		self.pub.pubkey_x, self.pub.pubkey_y = self.pub.key_uncompress(pub)

		if len(path) > 68:
			for d in A2MXStream.parse(path):
				if len(d) != 3:
					raise InvalidDataException('unparseable path')
				self.nextpath = A2MXPath(*d)
		else:
			self.endnode = ECC()
			self.endnode.pubkey_x, self.endnode.pubkey_y = self.endnode.key_uncompress(path)

		data = b''.join((path, pub))
		if self.nextpath:
			verify = self.nextpath.pub.verify(signature, data)
		else:
			verify = self.endnode.verify(signature, data)
		if not verify:
			raise InvalidDataException('signature failure')
		self.path = path
		self.signature = signature

	def __str__(self):
		return "({}, {})".format(ECC.b58(self.endnode.pubkey_hash()).decode('ascii') if self.endnode else str(self.nextpath), ECC.b58(self.pub.pubkey_hash()).decode('ascii'))

class A2MXNodelist():
	def __init__(self):
		self.rlist = []
		self.wlist = []
		self.networkInfo = {}
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

	def new_path(self, path, mypub, signature, stream):
		p = A2MXPath(path, mypub, signature)
		print("new_path", p)
		if p.pub.get_pubkey() != self.ecc.get_pubkey():
			raise InvalidDataException('path not for me?')

		nodes = []
		x = p
		while x:
			nodes.append(x.pub.get_pubkey())
			if x.endnode:
				nodes.append(x.endnode.get_pubkey())
			x = x.nextpath
		for stream in filter(lambda s: isinstance(s, A2MXStream), self.rlist):
			if stream.remote_ecc.get_pubkey() in nodes:
				continue

			print("INFORM STREAM", ECC.b58(stream.remote_ecc.pubkey_hash()).decode('ascii'))
			oldpath = stream.request(p.path, p.pub.pubkey_c(), p.signature)
			data = bytearray()
			data += oldpath
			data += stream.remote_ecc.pubkey_c()
			data = bytes(data)
			r = stream.request(b'I', oldpath, stream.remote_ecc.pubkey_c(), self.ecc.sign(data))
			stream.send(r)

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


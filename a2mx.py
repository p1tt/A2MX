#!/usr/bin/env python3

import sys
import socket
import select
import struct
import os

from ecc import ECC

from config import config

class Unbuffered:
	def __init__(self, stream):
		self.stream = stream
	def write(self, data):
		self.stream.write(data)
		self.stream.flush()
	def __getattr__(self, attr):
		return getattr(self.stream, attr)

sys.stdout=Unbuffered(sys.stdout)

class InvalidDataException(Exception):
	pass

class A2MXServer():
	def __init__(self, node, bind):
		self.node = node

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setblocking(0)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(bind)
		print("bound to", bind)
		self.sock.listen(5)
		self.node.add(self)

	def fileno(self):
		return self.sock.fileno()

	def select_r(self):
		sock, addr = self.sock.accept()
		A2MXStream(self.node, sock=sock)

	def select_w(self):
		assert False
	def select_e(self):
		assert False

	def finish(self):
		self.sock.close()
		self.node.remove(self)

def A2MXRequest(fn):
	fn.A2MXRequest__marker__ = True
	return fn

class A2MXStream():
	def __init__(self, node=None, uri=None, sock=None):
		assert node != None
		assert (uri == None and sock != None) or (uri != None and sock == None)
		self.node = node
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
			self.node.wadd(self)

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
			self.node.wremove(self)
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
		self.node.add(self)
		if self.uri != None:
			self.__send_pub()

	def __send_pub(self):
		ecc = self.node.ecc
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

		ecc = self.node.ecc
		if self.__pub_sent:		# if we sent our public key then all data we receive has to be encrypted
			data = ecc.decrypt(bytes(data))

		if self.remote_ecc == None:	# first data we expect is the compressed remote public key
			pubkey_x, pubkey_y = ecc.key_uncompress(data)
			self.remote_ecc = ECC(pubkey_x=pubkey_x, pubkey_y=pubkey_y)

			# ok we have the remote public key, from now on we send everything encrypted
			self.__raw_send = self.send
			self.send = self.encrypted_send

			if not self.__pub_sent:	# send our public key if we haven't already
				self.__send_pub()

			# send the remote public key signed by us
			self.send(ecc.sign(self.remote_ecc.get_pubkey()))
		elif not self.__remote_auth:	# second data is our own public key signed by remote
			auth = self.remote_ecc.verify(bytes(data), ecc.get_pubkey())
			if not auth:
				raise InvalidDataException('failed to verify remote')
			self.__remote_auth = True
			self.node.add_stream(self)
			print("connection up with", ECC.b58(self.remote_ecc.pubkey_hash()).decode('ascii'))

			p = A2MXPath(ecc, self.remote_ecc)
			self.node.new_path(p)
			if self.uri != None:
				r = self.request('pull')
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

	def send(self, data):
		self.sock.send(struct.pack('>L', len(data)), socket.MSG_MORE)
		self.sock.send(data)

	def encrypted_send(self, *data):
		data = b''.join(data)
		data = self.node.ecc.encrypt(data, self.remote_ecc.get_pubkey())
		self.__raw_send(data)

	def finish(self):
		print("finish")
		self.sock.close()
		self.node.del_stream(self)
		self.node.remove(self)

	@A2MXRequest
	def path(self, path):
		p = A2MXPath(data=path)
		p.stream = self
		self.node.new_path(p)

	@A2MXRequest
	def pull(self):
		for pathlist in self.node.paths.values():
			for path in pathlist:
				r = self.request('path', path.data)
				self.send(r)

	@A2MXRequest
	def disappear(self, path):
		raise NotImplemented()

	@A2MXRequest
	def flush(self, node):
		raise NotImplemented()

	@A2MXRequest
	def send(self, node, data):
		raise NotImplemented()

class A2MXPath():
	def __init__(self, endnode=None, lasthop=None, signature=None, data=None):
		if (endnode == None and lasthop == None and signature == None and data != None):
			endnode = data[:68]
			lasthop = data[68:2*68]
			signature = data[2*68:]
		elif (endnode != None and lasthop != None and data == None):
			pass
		else:
			raise ValueError()

		if not isinstance(lasthop, ECC):
			self.lasthop = ECC()
			self.lasthop.pubkey_x, self.lasthop.pubkey_y = self.lasthop.key_uncompress(lasthop)
		else:
			self.lasthop = lasthop

		if not isinstance(endnode, ECC):
			self.endnode = ECC()
			self.endnode.pubkey_x, self.endnode.pubkey_y = self.endnode.key_uncompress(endnode)
			if signature == None:
				raise ValueError()
		else:
			self.endnode = endnode

		sigdata = b''.join((self.endnode.get_pubkey(), self.lasthop.get_pubkey()))
		if signature == None:
			self.signature = self.endnode.sign(sigdata)
		else:
			verify = self.endnode.verify(signature, sigdata)
			if not verify:
				raise InvalidDataException('signature failure')

			self.signature = signature

	@property
	def data(self):
		return self.endnode.pubkey_c() + self.lasthop.pubkey_c() + self.signature

	def __eq__(self, other):
		if not isinstance(other, A2MXPath):
			raise TypeError()
		return self.endnode.get_pubkey() == other.endnode.get_pubkey() and self.lasthop.get_pubkey() == other.lasthop.get_pubkey()

	def __str__(self):
		return 'Endnode: {} Lasthop: {}'.format(ECC.b58(self.endnode.pubkey_hash()).decode('ascii'), ECC.b58(self.lasthop.pubkey_hash()).decode('ascii'))

class A2MXNode():
	def __init__(self, selectloop):
		self.selectloop = selectloop

		self.paths = {}
		self.streams = []
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
		mypub = ECC.b58(self.ecc.pubkey_hash()).decode('ascii')
		if sys.stdout.isatty():
			cwd = os.getcwd().rsplit('/', 1)[1]
			sys.stdout.write("\x1b]2;{}: {}\x07".format(cwd, mypub))
		print("I am", mypub)

	def add(self, selectable):
		self.selectloop.add(selectable)
	def remove(self, selectable):
		self.selectloop.remove(selectable)
	def wadd(self, selectable):
		self.selectloop.wadd(selectable)
	def wremove(self, selectable):
		self.selectloop.wremove(selectable)

	def add_stream(self, stream):
		assert stream not in self.streams
		self.streams.append(stream)
	def del_stream(self, stream):
		assert stream in self.streams
		self.streams.remove(stream)

	def new_path(self, path):
		# save path
		endpub = bytes(path.endnode.pubkey_c())
		try:
			pathlist = self.paths[endpub]
		except KeyError:
			self.paths[endpub] = []
			pathlist = self.paths[endpub]
			print("node discovered", ECC.b58(path.endnode.pubkey_hash()).decode('ascii'))
		if path not in pathlist:
			pathlist.append(path)
		else:
			return

		print("new_path", path)
		try:
			stream = path.stream
		except AttributeError:
			stream = None
		for ostream in self.streams:
			if ostream == stream:
				continue
			ostream.send(ostream.request('path', path.data))

class SelectLoop():
	def __init__(self):
		self.rlist = []
		self.wlist = []

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

selectloop = SelectLoop()

node = A2MXNode(selectloop)
for bind in config['bind']:
	server = A2MXServer(node, bind)

for uri in config['targets']:
	print("connect to", uri)
	c = A2MXStream(node, uri=uri)

try:
	while True:
		selectloop.select()
except KeyboardInterrupt:
	selectloop.shutdown()


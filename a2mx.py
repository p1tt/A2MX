#!/usr/bin/env python3

import sys
import socket
import select
import struct
import os
import datetime

from ecc import ECC
from bson import BSON

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

	def shutdown(self):
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

		self.send = self.raw_send
		self.remote_ecc = None
		self.__connected = False
		self.__remote_auth = False
		self.__pub_sent = False
		self.incoming_path = None
		self.outgoing_path = None
		self.send_updates = False

		if sock:
			self.sock = sock
			self.sock.setblocking(0)
			self.connected()
		elif uri != None:
			self.connect()
		else:
			raise ValueError('Invalid arguments to A2MXStream')

	def connect(self):
		uri = self.uri
		assert uri.startswith('ax://')
		hostport = uri[5:].split(':')
		assert len(hostport) >= 1
		host = hostport[0]
		if len(hostport) == 1:
			port = 0xA22
		elif len(hostport) == 2:
			port = int(hostport[1])
		else:
			assert False

		print("connect to", self.uri)

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setblocking(0)
		self.node.wadd(self)
		try:
			self.sock.connect((host, port))
		except BlockingIOError as e:
			if e.errno != 115:
				raise

	def fileno(self):
		return self.sock.fileno()

	def select_r(self):
		try:
			data = self.sock.recv(4096)
		except (ConnectionResetError, OSError):
			data = False
		if not data:
			self.connectionfailure()
			return
		self.data += data
		while len(self.data) >= self.handler[0]:
			self.handler[1](self.handler[0])
			if not self.__connected:
				break

	def select_w(self):
		if not self.__connected:
			self.node.wremove(self)
			self.connected()
		else:
			assert False

	def select_e(self):
		print("select_e")
		self.connectionfailure()

	def connected(self):
		self.__connected = True
		self.data = bytearray()
		self.handler = (4, self.getlength)
		self.node.add(self)
		if self.uri:
			self.__send_pub()

	def __send_pub(self):
		self.send(self.node.ecc.pubkey_c())
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
			self.incoming_path = p
			self.node.new_path(p)
		else:
			for fn, (args, kwargs) in self.parse(data).items():
				try:
					f = getattr(self, fn)
				except AttributeError:
					pass
				else:
					if hasattr(f, 'A2MXRequest__marker__') and f.A2MXRequest__marker__ == True:
						f(*args, **kwargs)
						continue
				print("Invalid request {}".format(fn))
		self.handler = (4, self.getlength)

	@staticmethod
	def parse(data):
		d = BSON.decode(data)
		print(d)
		return d

	@staticmethod
	def checkvalue(value):
		if isinstance(value, bytearray):
			return bytes(value)
		elif isinstance(value, (bytes, str, datetime.datetime)):
			return value
		else:
			raise ValueError('Invalid type in args')

	@staticmethod
	def request(fn, *args, **kwargs):
		a = [ A2MXStream.checkvalue(arg) for arg in args ]
		kw = {}
		for k, v in kwargs.items():
			kw[k] = A2MXStream.checkvalue(v)
		return BSON.encode({fn: (a, kw)})

	def raw_send(self, data):
		if not self.__connected:
			return False
		try:
			self.sock.send(struct.pack('>L', len(data)), socket.MSG_MORE)
			self.sock.send(data)
			return True
		except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError):
			self.connectionfailure()
		return False

	def encrypted_send(self, *data):
		if not self.__connected:
			return False
		data = b''.join(data)
		data = self.node.ecc.encrypt(data, self.remote_ecc.get_pubkey())
		return self.raw_send(data)

	def shutdown(self):
		self.sock.close()
		self.node.del_stream(self)
		self.node.remove(self)

		self.send = self.raw_send
		self.remote_ecc = None
		self.__connected = False
		self.__remote_auth = False
		self.__pub_sent = False
		self.incoming_path = None
		self.outgoing_path = None

		self.data = None

	def connectionfailure(self):
		self.shutdown()
		print(self.uri, "connection failure")
		if self.uri:
			self.node.selectloop.tadd(5, self.connect)

	@A2MXRequest
	def path(self, path):
		p = A2MXPath(data=path)
		if p.lasthop.get_pubkey() == self.node.ecc.get_pubkey() and p.endnode.get_pubkey() == self.remote_ecc.get_pubkey():
			self.outgoing_path = p
		p.stream = self
		self.node.new_path(p)

	@A2MXRequest
	def pull(self, timestamp):
		print("pull from", ECC.b58(self.remote_ecc.pubkey_hash()).decode('ascii'))
		for pathlist in self.node.paths.values():
			for path in pathlist:
				r = self.request('path', path.data)
				self.send(r)
		self.send_updates = True

	@A2MXRequest
	def decline(self):
		if not self.node.update_stream == self:
			print("decline on non update stream.")
			return
		

	@A2MXRequest
	def disappear(self, path):
		p = A2MXPath(data=path)
		self.node.del_path(p)

	@A2MXRequest
	def flush(self, node):
		raise NotImplemented()

	@A2MXRequest
	def sendto(self, node, data):
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
		self.stream = None

	@property
	def data(self):
		return self.endnode.pubkey_c() + self.lasthop.pubkey_c() + self.signature

	@property
	def endpub(self):
		return self.endnode.pubkey_hash()

	def __eq__(self, other):
		if not isinstance(other, A2MXPath):
			return False
		return self.endnode.get_pubkey() == other.endnode.get_pubkey() and self.lasthop.get_pubkey() == other.lasthop.get_pubkey()

	def __str__(self):
		return 'Endnode: {} Lasthop: {}'.format(ECC.b58(self.endnode.pubkey_hash()).decode('ascii'), ECC.b58(self.lasthop.pubkey_hash()).decode('ascii'))

class A2MXRoute():
	def __init__(self, routes):
		self.routes = routes

	def __len__(self):
		return len(self.routes)

	def __str__(self):
		s = 'A2MXRoute'
		for r in self.routes:
			s += ' ' + ECC.b58(r).decode('ascii')
		return s

class A2MXNode():
	def __init__(self, selectloop):
		self.selectloop = selectloop

		self.paths = {}
		self.streams = []
		self.update_stream = None
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

		if self.update_stream == None:
			self.update_stream = stream
			r = stream.request('pull', datetime.datetime.min)
			stream.send(r)

	def del_stream(self, stream):
		if stream not in self.streams:
			return
		self.streams.remove(stream)
		if stream == self.update_stream:
			if len(self.streams) == 0:
				self.update_stream = None
				print("no streams left for updates")
			else:
				self.update_stream = self.streams[0]
		self.del_path(stream.incoming_path)
		if stream.outgoing_path:
			self.del_path(stream.outgoing_path)

	def new_path(self, path):
		# save path
		endpub = path.endpub
		try:
			pathlist = self.paths[endpub]
		except KeyError:
			self.paths[endpub] = []
			pathlist = self.paths[endpub]
			print("node discovered", ECC.b58(path.endnode.pubkey_hash()).decode('ascii'))
		if path not in pathlist:
			pathlist.append(path)
		else:
			print("path", path, "known. ignoring.")
			return

		print("new_path", path)
		for ostream in self.streams:
			if ostream == path.stream or (not ostream.send_updates and ostream != self.update_stream):
				continue
			print("sending", path, "to", ECC.b58(ostream.remote_ecc.pubkey_hash()).decode('ascii'))
			ostream.send(ostream.request('path', path.data))

	def del_path(self, path):
		try:
			self.paths[path.endpub].remove(path)
		except (ValueError, KeyError):
			return
		print("del_path", path)
		for ostream in self.streams:
			ostream.send(ostream.request('disappear', path.data))

	def find_routes_from(self, src, dst, maxhops=None):
		if dst not in self.paths:
			return []
		pathlist = self.paths[dst]
		if len(pathlist) == 0:
			return []

		def find_path(pathlist, thispath=None, step=1):
			if maxhops != None and step >= maxhops:
				return
			if thispath == None:
				thispath = [dst]
			for path in pathlist:
				lasthop = path.lasthop.pubkey_hash()
				if lasthop == src:
					ytp = thispath[:]
					ytp.append(lasthop)
					yield A2MXRoute(ytp)
					continue
				if lasthop == dst:
					continue
				if lasthop in thispath:
					continue
				tp = thispath[:]
				tp.append(lasthop)
				for p in find_path(self.paths[lasthop], tp, step+1):
					yield p
		return find_path(pathlist)

	def shortest_route(self, src, dst):
		try:
			routes = [ x for x in self.find_routes_from(src, dst) ]
		except KeyError:
			return A2MXRoute([])
		if len(routes) == 0:
			return A2MXRoute([])
		return min(routes, key=len)

class SelectLoop():
	def __init__(self):
		self.rlist = []
		self.wlist = []
		self.tlist = []

	def add(self, selectable):
		self.rlist.append(selectable)
	def remove(self, selectable):
		try:
			self.rlist.remove(selectable)
		except ValueError:
			pass
	def wadd(self, selectable):
		self.wlist.append(selectable)
	def wremove(self, selectable):
		try:
			self.wlist.remove(selectable)
		except ValueError:
			pass
	def tadd(self, seconds, call, *args, **kwargs):
		callat = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
		self.tlist.append((callat, call, args, kwargs))
		self.tlist.sort(key=lambda tup: tup[0])

	def select(self):
		timeout = None
		if len(self.tlist) > 0:
			timeout = (self.tlist[0][0] - datetime.datetime.now()).total_seconds()
			if timeout < 0:
				timeout = 0
		r, w, e = select.select(self.rlist, self.wlist, self.rlist, timeout)
		for sock in e:
			sock.select_e()
		for sock in w:
			sock.select_w()
		for sock in r:
			sock.select_r()
		while len(self.tlist) > 0:
			if self.tlist[0][0] <= datetime.datetime.now():
				self.tlist[0][1](*self.tlist[0][2], **self.tlist[0][3])
				del self.tlist[0]
			else:
				break

	def shutdown(self):
		for sock in set(self.rlist + self.wlist):
			sock.shutdown()

selectloop = SelectLoop()

node = A2MXNode(selectloop)
for bind in config['bind']:
	server = A2MXServer(node, bind)

for uri in config['targets']:
	c = A2MXStream(node, uri=uri)

if config['client_interface']:
	from clientinterface import A2MXXMLRPCServer
	xmlrpcserver = A2MXXMLRPCServer(node, config['client_interface'])
	selectloop.add(xmlrpcserver)

try:
	while True:
		selectloop.select()
except KeyboardInterrupt:
#	selectloop.shutdown()
	pass


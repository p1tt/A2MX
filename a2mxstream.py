import socket
import struct
import datetime
from collections import OrderedDict
import ssl

from bson import BSON

class InvalidDataException(Exception):
	pass

from config import config
from ecc import ECC

from a2mxpath import A2MXPath

def SSL(sock, server=False):
	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
	context.verify_mode = ssl.CERT_NONE
	context.set_ecdh_curve('secp521r1')
	context.options = ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
	context.set_ciphers('ECDHE-ECDSA-AES256-SHA')
	if server:
		context.load_cert_chain(config['cert.pem'], config['key.pem'])
	return context.wrap_socket(sock, server_side=server, do_handshake_on_connect=False)

def A2MXRequest(fn):
	fn.A2MXRequest__marker__ = True
	fn.A2MXRequest__signature_required__ = False
	return fn

def A2MXRequest_Signed(fn):
	fn.A2MXRequest__marker__ = True
	fn.A2MXRequest__signature_required__ = True
	return fn

class A2MXStream():
	def __init__(self, node=None, uri=None, sock=None):
		assert node != None
		assert (uri == None and sock != None) or (uri != None and sock == None)
		self.node = node
		self.uri = uri

		self.bytes_in = 0
		self.bytes_out = 0
		self.cleanstate()

		if sock:
			self.sock = sock
			self.sock.setblocking(0)
			self.connected()
		elif uri != None:
			self.connect()
		else:
			raise ValueError('Invalid arguments to A2MXStream')

	def cleanstate(self):
		self.node.wremove(self)
		self.node.remove(self)

		self.send = self.raw_send
		self.remote_ecc = None
		self.__connected = False
		self.__remote_auth = False
		self.__pub_sent = False
		self.incoming_path = None
		self.outgoing_path = None
		self._data = None
		self.__select_r_fun = None
		self.__select_w_fun = None

	def __str__(self):
		return '{} Remote: {} In: {}B Out: {}B{}'.format(
			'Incoming' if self.uri == None else 'Outgoing', self.remote_ecc.b58_pubkey_hash(),
			self.bytes_in, self.bytes_out, ' disconnected' if not self.__connected else '')

	def connect(self):
		assert self.__connected == False
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
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		self.node.wadd(self)
		try:
			self.sock.connect((host, port))
		except BlockingIOError as e:
			if e.errno != 115:
				raise

	def fileno(self):
		return self.sock.fileno()

	def select_r(self):
		if self.__select_r_fun:
			self.__select_r_fun[0](*self.__select_r_fun[1], **self.__select_r_fun[2])
			return
		try:
			data = self.sock.recv(4096)
		except ssl.SSLWantReadError:
			return
		except (ConnectionResetError, OSError) as e:
			data = False
		if not data:
			self.connectionfailure()
			return
		self._data += data
		self.bytes_in += len(data)
		while len(self._data) >= self.handler[0]:
			self.handler[1](self.handler[0])
			if not self.__connected:
				break

	def select_w(self):
		if self.__select_w_fun:
			self.__select_w_fun[0](*self.__select_w_fun[1], **self.__select_w_fun[2])
			return
		if not self.__connected:
			self.node.wremove(self)
			self.connected()
		else:
			print("A2MXStream", self, self.node.selectloop.wlist)
			assert False

	def select_e(self):
		print("select_e")
		self.connectionfailure()

	def connected(self):
		# test sock connected
		try:
			self.sock.send(b'')
		except ConnectionRefusedError:
			self.connectionfailure()
			return

		self.sock = SSL(self.sock, server=self.uri == None)

		def do_handshake():
			try:
				self.sock.do_handshake()
			except ssl.SSLWantReadError:
				return
			except ssl.SSLWantWriteError:
				return
			except ssl.SSLError:
				pass
			self.node.wremove(self)
			self.__select_w_fun = None
			self.__select_r_fun = None

			self.__connected = True
			self._data = bytearray()
			self.handler = (4, self.getlength)
			if self.uri:
				self.__send_pub()

		self.__select_w_fun = (do_handshake, [], {})
		self.__select_r_fun = (do_handshake, [], {})
		self.node.add(self)
		self.node.wadd(self)
		do_handshake()

	def __send_pub(self):
		self.send(self.node.ecc.pubkey_c())
		self.__pub_sent = True

	def getlength(self, length):
		assert len(self._data) >= 4
		length = struct.unpack_from('>L', self._data[:4])[0]
		del self._data[:4]
		self.handler = (length, self.getdata)

	def getdata(self, length):
		assert len(self._data) >= length
		data = self._data[:length]
		del self._data[:length]

		ecc = self.node.ecc
		if self.__pub_sent:		# if we sent our public key then all data we receive has to be encrypted
			data = ecc.decrypt(bytes(data))

		if self.remote_ecc == None:	# first data we expect is the compressed remote public key
			self.remote_ecc = ECC(pubkey_compressed=data)

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
			print("incoming" if self.uri == None else "outgoing", "connection up with", self.remote_ecc.b58_pubkey_hash())
			if not self.node.add_stream(self):
				print("add_stream == False")
				self.shutdown()
				return

			p = A2MXPath(ecc, self.remote_ecc, axuri=config['publish_axuri'])
			self.incoming_path = p
			self.node.new_path(p)
		else:
			def parseRequest(request):
				def exfn(fn, args, kwargs, signature):
					f = getattr(self, fn, None)
					if getattr(f, 'A2MXRequest__marker__', False) == True:
						nextrequest = kwargs.pop('next', None)
						if f.A2MXRequest__signature_required__:
							sigok = signature and self.remote_ecc.verify(signature, BSON.encode({ fn: (args, kwargs) }))
						if not f.A2MXRequest__signature_required__ or sigok:
							waitseconds = f(*args, **kwargs)
							if waitseconds:
								yield waitseconds
							if not nextrequest:
								return
							parseRequest(nextrequest.items())
							return
					print("Invalid request {}({}, {}) {}".format(fn, args, kwargs, 'signed' if sigok else 'invalid signed' if signature else 'unsigned'))

				for fn, argtuple in request:
					if len(argtuple) == 2:
						args, kwargs = argtuple
						sig = None
					elif len(argtuple) == 3:
						args, kwargs, sig = argtuple
					else:
						raise InvalidDataException('Malformed request.')
					yd = exfn(fn, args, kwargs, sig)
					try:
						value = next(yd)
					except StopIteration:
						pass
					else:
						def f():
							try:
								next(yd)
							except StopIteration:
								pass
						self.node.selectloop.tadd(value, f)
			parseRequest(self.parse(data).items())
		self.handler = (4, self.getlength)

	@staticmethod
	def parse(data):
		d = BSON.decode(data, as_class=OrderedDict, tz_aware=True)
		return d

	@staticmethod
	def checkvalue(value):
		if isinstance(value, bytearray):
			return bytes(value)
		elif isinstance(value, (int, bytes, str, datetime.datetime, type(None), dict, OrderedDict)):
			return value
		else:
			raise ValueError('Invalid type in args {} = {}'.format(type(value), value))

	def request(self, fn, *args, request=None, **kwargs):
		if request == None:
			request = OrderedDict()
		else:
			assert isinstance(request, OrderedDict)

		a = [ A2MXStream.checkvalue(arg) for arg in args ]
		kw = {}
		for k, v in kwargs.items():
			kw[k] = A2MXStream.checkvalue(v)
		request[fn] = (a, kw)

		fun = getattr(self, fn, False)
		if not fun or not getattr(fun, 'A2MXRequest__marker__', False):
			raise ValueError('Unknown request: {}'.format(fn))
		if fun.A2MXRequest__signature_required__:
			if 'next' in kw:
				r = request.copy()
				del r[fn][1]['next']
			else:
				r = request
			sigdata = BSON.encode(r)
			sig = self.node.ecc.sign(sigdata)
			request[fn] = (a, kw, sig)
		return request

	def raw_send(self, data, wremove=False):
		if not self.__connected:
			return
		try:
			self.sock.sendall(struct.pack('>L', len(data)) + data)
		except ssl.SSLWantWriteError:
			print('SSLWantWriteError raised, this codepath is heavily untested.')
			self.__select_w_fun = (self.raw_send, [data], { 'wremove': True })
			if not wremove:
				self.node.wadd(self)
		except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError):
			self.connectionfailure()
		else:
			self.bytes_out += len(data) + 4
		if wremove:
			self.node.wremove(self)
			self.__select_w_fun = None

	def encrypted_send(self, data):
		if not self.__connected:
			return False
		if isinstance(data, OrderedDict):
			data = BSON.encode(data)
		data = self.node.ecc.encrypt(bytes(data), self.remote_ecc.get_pubkey())
		return self.raw_send(data)

	def shutdown(self):
		try:
			self.sock.shutdown(socket.SHUT_RDWR)
		except OSError:
			pass
		self.sock.close()
		self.node.del_stream(self)
		self.cleanstate()

	def connectionfailure(self):
		print(self.remote_ecc.b58_pubkey_hash() if self.remote_ecc else self.uri, "connection failure")
		self.shutdown()

	@A2MXRequest
	def path(self, **kwargs):
		if kwargs['lasthop'] == self.node.ecc.pubkey_c():
			kwargs['lasthop'] = self.node.ecc
		p = A2MXPath(**kwargs)
		if p.lasthop.get_pubkey() == self.node.ecc.get_pubkey() and p.endnode.get_pubkey() == self.remote_ecc.get_pubkey():
			self.outgoing_path = p
		p.stream = self
		self.node.new_path(p)

	@A2MXRequest_Signed
	def pull(self, timestamp):
		print("pull from", self.remote_ecc.b58_pubkey_hash(), timestamp)
		for path in self.node.paths:
			if path.newest_timestamp < timestamp:
				continue
			r = self.request('path', **path.data)
			self.send(r)

	@A2MXRequest_Signed
	def decline(self):
		if not self.node.update_stream == self:
			print("decline on non update stream.")
			return

	@A2MXRequest
	def flush(self, node, timestamp, signature):
		# this command must be signed by the originating node and invalidates all paths
		# the node is part of.
		raise NotImplemented()

	@A2MXRequest
	def sendto(self, node, data):
		if node not in self.node.nodes:
			print('cannot sendto {} node not directly connected to me.'.format(ECC(pubkey_compressed=node).b58_pubkey_hash()))
			return
		self.node.nodes[node].raw_send(data)

	@A2MXRequest
	def data(self, data):
		print("got data command", data)

	@A2MXRequest
	def discard(self, *args, **kwargs):
		pass

	@A2MXRequest
	def sleep(self, seconds):
		print("sleep for {}".format(seconds))
		return seconds


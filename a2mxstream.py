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
		self.bytes_in = 0
		self.bytes_out = 0
		self.__select_r_fun = None
		self.__select_w_fun = None

		if sock:
			self.sock = sock
			self.sock.setblocking(0)
			self.connected()
		elif uri != None:
			self.connect()
		else:
			raise ValueError('Invalid arguments to A2MXStream')

	def __str__(self):
		return '{} Remote: {} Updates: {} In: {}B Out: {}B{}'.format(
			'Incoming' if self.uri == None else 'Outgoing', ECC.b58(self.remote_ecc.pubkey_hash()).decode('ascii'),
			self.send_updates, self.bytes_in, self.bytes_out, ' disconnected' if not self.__connected else '')

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
			print("got remote pubkey", ECC.b58(self.remote_ecc.pubkey_hash()).decode('ascii'))

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
			print("incoming" if self.uri == None else "outgoing", "connection up with", ECC.b58(self.remote_ecc.pubkey_hash()).decode('ascii'))

			p = A2MXPath(ecc, self.remote_ecc, axuri=config['publish_axuri'])
			self.incoming_path = p
			self.node.new_path(p)
		else:
			def parseRequest(request):
				def exfn(fn, args, kwargs):
					try:
						f = getattr(self, fn)
					except AttributeError:
						pass
					else:
						if hasattr(f, 'A2MXRequest__marker__') and f.A2MXRequest__marker__ == True:
							nextrequest = kwargs.pop('next', None)
							waitseconds = f(*args, **kwargs)
							if waitseconds:
								yield waitseconds
							if not nextrequest:
								return
							parseRequest(nextrequest.items())
							return
					print("Invalid request {}({}, {})".format(fn, args, kwargs))

				for fn, (args, kwargs) in request:
					yd = exfn(fn, args, kwargs)
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

	@staticmethod
	def request(fn, *args, request=None, **kwargs):
		if request == None:
			request = OrderedDict()
		else:
			assert isinstance(request, OrderedDict)

		a = [ A2MXStream.checkvalue(arg) for arg in args ]
		kw = {}
		for k, v in kwargs.items():
			kw[k] = A2MXStream.checkvalue(v)
		request[fn] = (a, kw)
		return request

	def raw_send(self, data):
		if not self.__connected:
			return False
		if isinstance(data, OrderedDict):
			data = BSON.encode(data)
		try:
			self.sock.send(struct.pack('>L', len(data)) + data)
			self.bytes_out += len(data) + 4
			return True
		except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError):
			self.connectionfailure()
		return False

	def encrypted_send(self, data):
		if not self.__connected:
			return False
		if isinstance(data, OrderedDict):
			data = BSON.encode(data)
		data = self.node.ecc.encrypt(bytes(data), self.remote_ecc.get_pubkey())
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

		self._data = None

	def connectionfailure(self):
		self.shutdown()
		print(self.uri, "connection failure")
		if self.uri:
			self.node.selectloop.tadd(5, self.connect)

	@A2MXRequest
	def path(self, **kwargs):
		if kwargs['lasthop'] == self.node.ecc.pubkey_c():
			kwargs['lasthop'] = self.node.ecc
		p = A2MXPath(**kwargs)
		if p.lasthop.get_pubkey() == self.node.ecc.get_pubkey() and p.endnode.get_pubkey() == self.remote_ecc.get_pubkey():
			self.outgoing_path = p
		p.stream = self
		self.node.new_path(p)

	@A2MXRequest
	def pull(self, timestamp):
		print("pull from", ECC.b58(self.remote_ecc.pubkey_hash()).decode('ascii'))
		for pathlist in self.node.paths.values():
			for path in pathlist:
				r = self.request('path', **path.data)
				self.send(r)
		self.send_updates = True

	@A2MXRequest
	def decline(self):
		if not self.node.update_stream == self:
			print("decline on non update stream.")
			return

	@A2MXRequest
	def flush(self, node):
		raise NotImplemented()

	@A2MXRequest
	def sendto(self, node, data):
		raise NotImplemented()

	@A2MXRequest
	def data(self, data):
		print("got data command", data)

	@A2MXRequest
	def sleep(self, seconds):
		print("sleep for {}".format(seconds))
		return seconds



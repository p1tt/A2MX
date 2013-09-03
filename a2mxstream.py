import socket
import struct
import datetime
from collections import OrderedDict
import ssl
import random

from bson import BSON

from config import config
from ecc import ECC

from a2mxpath import A2MXPath
from a2mxdirect import A2MXDirect
from a2mxcommon import InvalidDataException
from a2mxrequest import A2MXRequest

def SSL(sock, server=False):
	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
	context.verify_mode = ssl.CERT_NONE
#	context.set_verify(ssl.VERIFY_PEER | ssl.VERIFY_FAIL_IF_NO_PEER_CERT | ssl.VERIFY_CLIENT_ONCE, callback_func)
	context.set_ecdh_curve('secp521r1')
	context.options = ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
	context.set_ciphers('ECDHE-ECDSA-AES256-SHA')
	if server:
		context.load_cert_chain(config['cert.pem'], config['key.pem'])
	return context.wrap_socket(sock, server_side=server, do_handshake_on_connect=False)

class A2MXStream():
	def __init__(self, node=None, uri=None, sock=None, pubkey_hash=None):
		assert node != None
		assert (uri == None and sock != None) or (uri != None and sock == None)
		self.node = node
		self.uri = uri

		self.bytes_in = 0
		self.bytes_out = 0
		self.cleanstate()
		self.remote_b58_pubkey_hash = pubkey_hash
		self.request = A2MXRequest(self.node, self)

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
		self.__last_recv = None
		self.__pub_sent = False
		self.incoming_path = None
		self.outgoing_path = None
		self._data = None
		self.__select_r_fun = None
		self.__select_w_fun = None
		self.__direct = False

	def __str__(self):
		return '{} Remote: {} Path: {} In: {}B Out: {}B{}'.format(
			'Incoming' if self.uri == None else 'Outgoing', self.remote_ecc.b58_pubkey_hash(),
			self.outgoing_path, self.bytes_in, self.bytes_out,
			' disconnected' if not self.__connected else '')

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
		if '@' in host:
			self.remote_b58_pubkey_hash, host = host.split('@')

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
		self.__last_recv = datetime.datetime.now(datetime.timezone.utc)
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
			except (ssl.SSLError, ConnectionResetError):
				self.connectionfailure()
				return
			self.node.wremove(self)
			self.__select_w_fun = None
			self.__select_r_fun = None

			self.__connected = True
			self._data = bytearray()
			self.handler = (3, self.getlength)
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
		assert len(self._data) >= 3
		ident, length = struct.unpack_from('>BH', self._data[:3])
		del self._data[:3]
		if length == 0:
			return
		if ident == 0:
			if self.__direct != False:
				raise InvalidDataException('Cannot mix requests on one stream')
			self.handler = (length, self.getdata)
		elif ident == 1:
			self.handler = (length, self.getdirectdata)
		else:
			raise InvalidDataException('Unknown ident')

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

			p = A2MXPath(ecc, self.remote_ecc, axuri=config['publish_axuri'])
			self.incoming_path = p
			self.send(self.request.request('path', **p.data))
		else:
			self.request.parseRequest(data)
		self.handler = (3, self.getlength)

	def getdirectdata(self, length):
		assert len(self._data) >= length
		data = self._data[:length]
		del self._data[:length]

		if self.__direct == False:
			def send(data):
				return self.raw_send(data, direct=True)
			self.__direct = A2MXDirect(self.node, send)
		self.__direct.process(data)
		self.handler = (4, self.getlength)

	def raw_send(self, data, wremove=False, direct=False):
		if not self.__connected:
			return
		try:
			self.sock.sendall(struct.pack('>BH', 1 if direct else 0, len(data)) + data)
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
		if self.__direct != False:
			self.__direct.disconnected()
		self.cleanstate()

	def connectionfailure(self):
		if self.__direct == False:
			print(self.remote_ecc.b58_pubkey_hash() if self.remote_ecc else self.uri, "connection failure")
		self.shutdown()

	def keepalive(self):
		if not self.__connected:
			return
		self.node.selectloop.tadd(random.randint(20, 45), self.keepalive)
		if self.__last_recv < datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=90):
			print("last receive is longer than 90 seconds ago!")
		print(datetime.datetime.now(), "keepalive")
		self.raw_send(b'')


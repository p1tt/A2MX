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
from a2mxaccess import A2MXAccess
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
		context.load_cert_chain(config['tls.cert.pem'], config['tls.key.pem'])
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
		self.remote_pubkey_hash = pubkey_hash
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
		self.path = None
		self._data = None
		self.__select_r_fun = None
		self.__select_w_fun = None
		self.__access = False
		self.__send_queue = []
		self.__recv_queue = {}

	def __str__(self):
		return '{} Remote: {} Path: {} In: {}B Out: {}B{}'.format(
			'Incoming' if self.uri == None else 'Outgoing', self.remote_ecc.b58_pubkey_hash(),
			self.path, self.bytes_in, self.bytes_out,
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
			b58_pubkey_hash, host = host.split('@')
			self.remote_pubkey_hash = ECC.b58decode(b58_pubkey_hash)

		print("connect to", self.uri)
		if self.remote_pubkey_hash == None:
			print("No remote public key hash given. This is NOT recommended.")

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
			self.handler = (7, self.getLength)
			if self.uri:
				self.__send_pub()

		self.__select_w_fun = (do_handshake, [], {})
		self.__select_r_fun = (do_handshake, [], {})
		self.node.add(self)
		self.node.wadd(self)
		do_handshake()

	def __send_pub(self):
		self.send(self.node.ecc.pubkeyCompressed())
		self.__pub_sent = True

	def getLength(self, length):
		assert len(self._data) >= 7
		assert length == 7
		ident, rid, length = struct.unpack_from('>BLH', self._data[:7])
		del self._data[:7]
		if length == 0:
			return
		print("getLength", ident, rid, length)

		def getRemainingData(length):
			self.handler = (7, self.getLength)
			data = self._data[:length]
			del self._data[:length]

			if rid not in self.__recv_queue:
				self.__recv_queue[rid] = data
			else:
				self.__recv_queue[rid] += data

		def getData(length):
			print("getData", length)
			self.handler = (7, self.getLength)
			data = self._data[:length]
			del self._data[:length]

			if rid in self.__recv_queue:
				data = self.__recv_queue[rid] + data
				del self.__recv_queue[rid]
			if ident == 0:
				if self.__access != False:
					raise InvalidDataException('Cannot mix requests on one stream')
				self.gotData(data)
			elif ident == 1:
				self.gotDirectData(data)
			elif ident == 2:
				self.gotAccessData(data)
			else:
				raise InvalidDataException('Unknown ident')

		if ident <= 3:
			self.handler = (length, getData)
		elif ident == 0xFF:
			self.handler = (length, getRemainingData)
		else:
			raise InvalidDataException('Unknown ident')

	def gotData(self, data):
		if self.__pub_sent:		# if we sent our public key then all data we receive has to be encrypted
			data = self.node.ecc.decrypt(data)
			if len(data) == 0:
				return

		if self.remote_ecc == None:	# first data we expect is the compressed remote public key
			self.remote_ecc = ECC(pubkey_compressed=data)

			if self.remote_pubkey_hash != None:
				if self.remote_ecc.pubkeyHash() != self.remote_pubkey_hash:
					raise ValueError("Remote public key hash doesn't match.")
			else:
				self.remote_pubkey_hash = self.remote_ecc.pubkeyHash()

			# ok we have the remote public key, from now on we send everything encrypted
			self.send = self.encrypted_send

			self.path = A2MXPath(self.node.ecc, self.remote_ecc)
			if not self.__pub_sent:	# send our public key if we haven't already
				self.__send_pub()
				self.send(self.request.request('path', **self.path.data))
		else:
			self.request.parseRequest(data)

	def gotAccessData(self, data):
		if self.__access == False:
			def send(data):
				return self.raw_send(data, access=True)
			self.__access = A2MXAccess(self.node, send)
		self.__access.process(data)

	def gotDirectData(self, data):
		request = A2MXRequest.parse(bytes(data))
		# currently only pull is supported hardcoded ... FIXME
		timestamp = request['pull'][0][0]
		print("got pull from", self.remote_ecc.pubkeyHashBase58(), timestamp)
		for path in self.node.paths:
			if path.newest_timestamp < timestamp:
				continue
			r = self.request.request('path', **path.data)
			self.send(r)

	def raw_send(self, data, access=False, direct=False):
		assert not (access and direct)
		if not self.__connected:
			return
		if isinstance(data, OrderedDict):
			data = BSON.encode(data)
		rid = random.randint(0, 0xFFFFFFFF)
		# split data
		while len(data) > 0:
			part = data[:0xFFFF]
			data = data[0xFFFF:]
			data_remaining = len(data) > 0
			first_byte = 0xFF if data_remaining else 1 if direct else 2 if access else 0
			print("first_byte", first_byte)

			pre = struct.pack('>BLH', first_byte, rid, len(part))
			self.__send_queue.append(pre + part)
			data = data[0xFFFF:]
		self.send_queue()

	def send_queue(self, data=None):
		if data == None:
			data = self.__send_queue.pop(0)
		try:
			self.sock.sendall(data)
		except ssl.SSLWantWriteError:
			print('SSLWantWriteError raised, this codepath is heavily untested.')
			self.__select_w_fun = (self.send_queue, (), { 'data': data })
			self.node.wadd(self)
			return
		except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError):
			self.connectionfailure()
		else:
			self.bytes_out += len(data)
		if len(self.__send_queue):
			self.__select_w_fun = (self.send_queue, (), {})
			self.node.wadd(self)
		else:
			self.__select_w_fun = None
			self.node.wremove(self)

	def encrypted_send(self, data, access=False, direct=False):
		assert not (access and direct)
		if not self.__connected:
			return False
		if isinstance(data, OrderedDict):
			data = BSON.encode(data)
		data = self.remote_ecc.encrypt(data)
		return self.raw_send(data, access, direct)

	def shutdown(self):
		try:
			self.sock.shutdown(socket.SHUT_RDWR)
		except OSError:
			pass
		self.sock.close()
		self.node.del_stream(self)
		if self.__access != False:
			self.__access.disconnected()
		self.cleanstate()

	def connectionfailure(self):
		if self.__access == False:
			print(self.remote_ecc.b58_pubkey_hash() if self.remote_ecc else self.uri, "connection failure")
		self.shutdown()


import socket
import struct
import datetime
from collections import OrderedDict
import ssl
import random
import sys
import traceback

from bson import BSON

from config import config
from ecc import ECC

import a2mxrequest

def SSL(sock, server=False):
	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
	context.verify_mode = ssl.CERT_NONE
	context.options = ssl.OP_SINGLE_DH_USE | ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_NO_COMPRESSION
	context.set_ciphers('DHE-RSA-AES256-GCM-SHA384')
	if server:
		context.load_dh_params(config['dh.pem'])
		context.load_cert_chain(config['tls.cert.pem'], config['tls.key.pem'])
	return context.wrap_socket(sock, server_side=server, do_handshake_on_connect=False)

def parseData(obj, onlink, data, send_callback):
	bs = BSON.decode(bytes(data), tz_aware=True, as_class=OrderedDict)

	result = {}
	def execute(request):
		def ex(fndict):
			assert isinstance(fndict, (dict, OrderedDict))
			f = getattr(obj, fndict['F'], None)
			if getattr(f, 'A2MXRequest__marker__', False) != True:
				raise ValueError('No A2MXRequest {} in {}'.format(fndict['F'], obj))
			if not onlink and getattr(f, 'A2MXRequest__marker__onlink', True) == True:
				raise ValueError('A2MXRequest {} can be called forwarded.')

			r = f(*fndict.get('A', []), **fndict.get('K', {}))
			rid = fndict.get('R', None)
			nextrequest = fndict.get('N', None)

			if isinstance(r, a2mxrequest.AsyncResult):
				def async(result):
					if nextrequest:
						execute(nextrequest)
					if rid:
						send_callback({ '0': (rid, result) })
				r.call_on_set = async
			elif rid:
				result[str(len(result))] = (rid, r)
			if nextrequest:
				execute(nextrequest)
		if '0' in request:
			i = 0
			while True:
				try:
					execute(request[str(i)])
				except KeyError:
					break
				i += 1
		else:
			ex(request)
	execute(bs)
	if len(result):
		send_callback(result)

class SessionSetup():
	def __init__(self, stream):
		self.stream = stream
		self.types = { 'Forward': a2mxrequest.Forward, 'Direct': a2mxrequest.Direct, 'Access': a2mxrequest.Access }

	@a2mxrequest.A2MXRequest()
	def A2MXv1(self, ClientTimestamp):
		print("ClientTimestamp", ClientTimestamp)
		now = datetime.datetime.now(datetime.timezone.utc)
		delta = datetime.timedelta(seconds=60)
		if ClientTimestamp < now - delta or ClientTimestamp > now + delta:
			print("ClientTimestamp", ClientTimestamp, now)
			raise ValueError('Timestamp too old, check system time.')
		ecc = self.stream.node.ecc
		pubkeyData = ecc.pubkeyData()
		self.stream.pub_sent = True
		return { 'PubKey': pubkeyData, 'PubKeySignature': ecc.signAddress(pubkeyData), 'TLSSignature': ecc.signAddress(self.stream.tlscert) }

	@a2mxrequest.A2MXRequest()
	def NewSession(self, Type):
		assert Type in self.types
		while True:
			session = random.randint(1, 0xFFFF)
			if session not in self.stream.sessions:
				break
		self.stream.sessions[session] = self.types[Type](self.stream)
		self.stream.sessions[session].sid = session
		return session

class A2MXStream():
	def __init__(self, node=None, uri=None, sock=None, pubkey_hash=None):
		assert node != None
		assert (uri == None and sock != None) or (uri != None and sock == None)
		self.node = node
		self.uri = uri
		self.remote_pubkey_hash = pubkey_hash

		self.server = uri == None
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

		self.sessions = { 0: SessionSetup(self) }
		self.callbacks = {}
		self.remote_ecc = None
		self.__connected = False
		self.__last_recv = None
		self.pub_sent = False
		self.path = None
		self._data = None
		self.__select_r_fun = None
		self.__select_w_fun = None
		self.__send_queue = []
		self.__recv_queue = {}

	def __str__(self):
		return '{} Remote: {} Path: {} In: {}B Out: {}B{}'.format(
			'Incoming' if self.uri == None else 'Outgoing', self.remote_ecc.pubkeyHashBase58(),
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
			self.handler[1]()
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

		self.sock = SSL(self.sock, server=self.server)
		if self.uri == None:
			with open(config['tls.cert.pem'], 'r') as f:
				pemcert = f.read()
			self.tlscert = ssl.PEM_cert_to_DER_cert(pemcert)
		else:
			self.tlscert = False

		def do_handshake():
			try:
				self.sock.do_handshake()
			except ssl.SSLWantReadError:
				return
			except ssl.SSLWantWriteError:
				self.node.wadd(self)
				return
			except (ssl.SSLError, ConnectionResetError) as e:
				self.connectionfailure()
				return
			self.node.wremove(self)
			self.__select_w_fun = None
			self.__select_r_fun = None

			self.__connected = True
			self._data = bytearray()
			self.tlsconnected()

		self.__select_w_fun = (do_handshake, [], {})
		self.__select_r_fun = (do_handshake, [], {})
		self.node.add(self)
		do_handshake()

	def tlsconnected(self):
		self.handler = (5, self.getHeader)
		if not self.server:
			def version_response(kwargs):
				PubKey = kwargs['PubKey']
				PubKeySignature = kwargs['PubKeySignature']
				TLSSignature = kwargs['TLSSignature']

				self.remote_ecc = ECC(pubkey_data=PubKey)
				if self.remote_pubkey_hash:
					if self.remote_ecc.pubkeyHash() != self.remote_pubkey_hash:
						raise ValueError('Public key hash does not match!')
				else:
					print('No remote public key hash given. This is not recommended!')
					self.remote_pubkey_hash = self.remote_ecc.pubkeyHash()
				if not self.remote_ecc.verifyAddress(PubKeySignature, PubKey):
					raise ValueError('PubKeySignature verification failed.')
				tlscert = self.sock.getpeercert(True)
				if not self.remote_ecc.verifyAddress(TLSSignature, tlscert):
					raise ValueError('TLSSignature verification failed.')
				print("TLS connection up")
				self.node.add_stream(self)

				self.forward = a2mxrequest.Forward(self, True)

			self.sendCall('A2MXv1', datetime.datetime.now(datetime.timezone.utc), callback=version_response)

	def data(self, onlink, session, data):
		if onlink == 2:
			bs = BSON.decode(bytes(data), tz_aware=True, as_class=OrderedDict)
			i = 0
			while True:
				try:
					rid, result = bs[str(i)]
				except KeyError:
					break
				self.callbacks[rid](result)
				del self.callbacks[rid]
				i += 1
			return

		def result_send(data):
			d = A2MXStream.prepareData(data)
			self.send(d, session=session, onlink=onlink, response=True)
		parseData(self.sessions[session], onlink, data, result_send)

	def getHeader(self):
		assert len(self._data) >= 5
		length, onlink, session = struct.unpack_from('>HBH', self._data[:5])
		del self._data[:5]
		if length == 0:
			return

		def getData():
			self.handler = (5, self.getHeader)
			assert len(self._data) >= length
			data = self._data[:length]
			del self._data[:length]

			if not onlink:
				data = self.node.ecc.decrypt(data)

			presize = struct.calcsize('>B')
			stripe = struct.unpack_from('>B', data[:presize])[0]
			if stripe != 0:
				presize += struct.calcsize('>LQQ')
				mid, total_length, offset = struct.unpack_from('>LQQ', data[1:presize])
				raise NotImplemented('store and save data... run if all received.')
			else:
				mid = 0
				total_length = len(data) - presize
				offset = 0
			self.data(onlink, session, data[presize:])
		self.handler = (length, getData)

	def send(self, data, session=0, onlink=True, response=False):
		if not self.__connected:
			return False
		assert isinstance(data, (bytearray, bytes))

		pre = struct.pack('>HBH', len(data), 2 if response else 1 if onlink else 0, session)
		self.__send_queue.append(pre + data)
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

	def shutdown(self):
		try:
			self.sock.shutdown(socket.SHUT_RDWR)
		except OSError:
			pass
		self.sock.close()
		self.node.del_stream(self)
		self.cleanstate()

	def connectionfailure(self):
		if sys.exc_info() != (None, None, None):
			traceback.print_exc()
		print(self.remote_ecc.pubkeyHashBase58() if self.remote_ecc else self.uri, "connection failure")
		self.shutdown()

	def sendCall(self, fn, *args, **kwargs):
		session = kwargs.pop('session', 0)
		onlink = kwargs.pop('onlink', True)
		call = self.prepareCall(fn, *args, **kwargs)
		data = self.prepareData(call)
		self.send(data, session=session, onlink=onlink)

	def prepareCall(self, fn, *args, **kwargs):
		nextcall = kwargs.pop('nextcall', None)
		callback = kwargs.pop('callback', None)
		assert isinstance(fn, str)
		a = OrderedDict()

		a['F'] = fn
		if len(args):
			a['A'] = args
		if len(kwargs):
			a['K'] = kwargs

		if callback:
			while True:
				rid = random.randint(1, 0xFFFFFFFF)
				if rid not in self.callbacks:
					break
			self.callbacks[rid] = callback
			a['R'] = rid

		if nextcall:
			assert isinstance(nextcall, (dict, OrderedDict))
			assert len(nextcall) == 1
			a['N'] = nextcall
		return a

	@staticmethod
	def prepareData(bs, *data, maxsize=0xFFFF, stripe=0):
		assert maxsize <= 0xFFFF
		maxsize -= struct.calcsize('>B')
		if isinstance(bs, (list, tuple)):
			bsdict = OrderedDict()
			v = 0
			for a in bs:
				bsdict[str(v)] = a
				v += 1
			bs = bsdict
		assert isinstance(bs, (dict, OrderedDict))

		if stripe != 0 and stripe != 1:
			raise NotImplemented('Stripe >1 currently not implemented.')
		first = True
		fulldata = bytearray(BSON.encode(bs))
		dataid = 1
		for d in data:
			if isinstance(d, (bytes, bytearray)):
				assert 'data{}'.format(dataid) in bs
				fulldata += struct.pack('>HQ', dataid, len(d))
				dataid += 1
				fulldata += d
			else:
				raise ValueError('Invalid argument.')
			first = False

		total_length = len(fulldata)
		if total_length < maxsize and stripe == 0:
			return struct.pack('>B', 0) + fulldata
		maxsize -= struct.calcsize('>LQQ')
		result = []
		if stripe == 0:
			stripe = 1
		mid = random.randint(1, 0xFFFFFFFF)
		offset = 0
		while len(fulldata):
			pre = struct.pack('>BLQQ', stripe, mid, total_length, offset)
			result.append(pre + fulldata[:maxsize])
			offset += len(fulldata[:maxsize])
			del fulldata[:maxsize]
		return result


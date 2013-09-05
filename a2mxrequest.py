import datetime
from collections import OrderedDict
from bson import BSON

from a2mxcommon import InvalidDataException
from a2mxpath import A2MXPath

def A2MXRequest(fn):
	fn.A2MXRequest__marker__ = True
	fn.A2MXRequest__signature_required__ = False
	return fn

def A2MXRequest_Signed(fn):
	fn.A2MXRequest__marker__ = True
	fn.A2MXRequest__signature_required__ = True
	return fn

class A2MXRequest():
	def __init__(self, node, stream=None):
		self.node = node
		self.stream = stream

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

		a = [ self.checkvalue(arg) for arg in args ]
		kw = {}
		for k, v in kwargs.items():
			kw[k] = self.checkvalue(v)
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

	def parseRequest(self, request):
		if isinstance(request, bytes):
			request = self.parse(request).items()

		def exfn(fn, args, kwargs, signature):
			if self.stream:
				if not self.stream.path.isComplete and fn != 'path':
					raise InvalidDataException('expecting path first')
			f = getattr(self, fn, None)
			if getattr(f, 'A2MXRequest__marker__', False) == True:
				nextrequest = kwargs.pop('next', None)
				if f.A2MXRequest__signature_required__:
					sigok = signature and self.stream.remote_ecc.verify(signature, BSON.encode({ fn: (args, kwargs) }))
				if not f.A2MXRequest__signature_required__ or sigok:
					if args != None:
						waitseconds = f(*args, **kwargs)
					else:
						waitseconds = f(**kwargs)
					if waitseconds:
						yield waitseconds
					if not nextrequest:
						return
					parseRequest(nextrequest.items())
					return
			print("Invalid request {}({}, {}) {}".format(fn, args, kwargs, 'unsigned' if not signature else 'signed' if sigok else 'invalid signed'))
	
		for fn, argtuple in request:
			if len(argtuple) == 1:
				args = None
				kwargs = argtuple[0]
				sig = None
			elif len(argtuple) == 2:
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

	@A2MXRequest
	def path(self, **kwargs):
		if kwargs['A'] == self.node.ecc.pubkeyCompressed():
			kwargs['A'] = self.node.ecc
		elif kwargs['B'] == self.node.ecc.pubkeyCompressed():
			kwargs['B'] = self.node.ecc
		p = A2MXPath(**kwargs)
		assert p.isComplete
		self.node.new_path(p, self.stream)
		if self.stream and self.stream.path == p and not self.stream.path.isComplete:
			self.stream.path = p
			print("incoming" if self.stream.uri == None else "outgoing", "connection up with", self.stream.remote_ecc.b58_pubkey_hash())
			if not self.node.add_stream(self.stream):
				print("add_stream == False")
				self.stream.shutdown()
				return

			try:
				last_known_path = self.node.paths[-2]
			except IndexError:
				last_known_path = datetime.datetime.min
			else:
				last_known_path = last_known_path.newest_timestamp
			r = self.request('pull', last_known_path)
			self.stream.send(r)
			self.stream.keepalive()

	@A2MXRequest_Signed
	def pull(self, timestamp):
		print("pull from", self.stream.remote_ecc.b58_pubkey_hash(), timestamp)
		for path in self.node.paths:
			if path.newest_timestamp < timestamp:
				continue
			r = self.request('path', **path.data)
			self.stream.send(r)

	@A2MXRequest_Signed
	def decline(self):
		raise NotImplemented()

	@A2MXRequest
	def flush(self, node, timestamp, signature):
		# this command must be signed by the originating node and invalidates all paths
		# the node is part of.
		raise NotImplemented()

	@A2MXRequest
	def sendto(self, node, data):
		self.node.sendto(node, data)

	@A2MXRequest
	def data(self, **kwargs):
		print("got data command", kwargs)

	@A2MXRequest
	def discard(self, *args, **kwargs):
		pass

	@A2MXRequest
	def sleep(self, seconds):
		print("sleep for {}".format(seconds))
		return seconds


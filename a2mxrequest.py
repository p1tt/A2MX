import random

from ecc import ECC
from a2mxpath import A2MXPath

from config import config

class A2MXRequest():
	def __init__(self, onlink=True):
		self.onlink = onlink
	def __call__(self, fn):
		fn.A2MXRequest__marker__ = True
		fn.A2MXRequest__marker__onlink = self.onlink
		return fn

class AsyncResult():
	@property
	def result(self):
		return self.__result
	@result.setter
	def result(self, value):
		self.__result = value
		self.call_on_set(value)
	@property
	def call_on_set(self):
		return self.__call_on_set
	@call_on_set.setter
	def call_on_set(self, value):
		self.__call_on_set = value
		if hasattr(self, '__result'):
			value(self.__result)

class Direct():
	def __init__(self, stream, send):
		print("init Direct")
		self.stream = stream

class Access():
	def __init__(self, stream, send):
		print("init Access")
		self.stream = stream

class Forward():
	def __init__(self, stream, setup=False):
		print("init Forward")
		self.stream = stream
		self.auth = False

		if setup:
			def forward_session(sid):
				self.sid = sid
				self.stream.sessions[sid] = self
				def authed(ok):
					self.auth = True
					def gotpath(path):
						ecc = self.stream.node.ecc
						if path['A'] == ecc.pubkeyData():
							path['A'] = ecc
							if path['B'] != self.stream.remote_ecc.pubkeyData():
								raise ValueError('Remote not included in path.')
							path['B'] = self.stream.remote_ecc
						elif path['B'] == ecc.pubkeyData():
							path['B'] = ecc
							if path['A'] != self.stream.remote_ecc.pubkeyData():
								raise ValueError('Remote not included in path.')
							path['A'] = self.stream.remote_ecc
						else:
							raise ValueError('Me not included in path.')
						path['P'] = True
						p = A2MXPath(**path)
						def pathfinished():
							assert p.isComplete
							self.sendCall('setpath', p.data)
							self.stream.path = p
							self.stream.node.new_path(self.stream.path, self.stream)
						p.pow_done = pathfinished
					self.sendCall('getpath', config['MaxSize'], config['PB'], config['PF'], config['PD'], callback=gotpath)
				self.stream.pub_sent = True
				pubkeyData = self.stream.node.ecc.pubkeyData()
				self.sendCall('Authenticate', pubkeyData, self.stream.node.ecc.signAddress(pubkeyData), callback=authed)
			self.stream.sendCall('NewSession', 'Forward', callback=forward_session)

	def sendCall(self, fn, *args, **kwargs):
		kwargs['session'] = self.sid
		return self.stream.sendCall(fn, *args, **kwargs)

	@A2MXRequest()
	def Authenticate(self, PubKey, PubKeySignature):
		ecc = ECC(pubkey_data=PubKey)
		if not ecc.verifyAddress(PubKeySignature, PubKey):
			raise ValueError('Failed to verify public key data.')
		self.stream.remote_ecc = ecc
		self.stream.send = self.stream.encrypted_send
		self.auth = True
		self.stream.node.add_stream(self.stream)
		return True

	@A2MXRequest()
	def getpath(self, MaxSize, PB, PF, PD):
		if MaxSize > config['MaxSize']:
			MaxSize = config['MaxSize']
		if PB < config['PB']:
			PB = config['PB']
		if PF < config['PF']:
			PB = config['PF']
		if PD < config['PD']:
			PB = config['PD']
		path = A2MXPath(A=self.stream.node.ecc, B=self.stream.remote_ecc, M=MaxSize, PB=PB, PF=PF, PD=PD)
		return path.data

	@A2MXRequest()
	def setpath(self, path):
		myPubkeyData = self.stream.node.ecc.pubkeyData()
		remotePubkeyData = self.stream.remote_ecc.pubkeyData()
		if path['A'] == myPubkeyData:
			path['A'] = self.stream.node.ecc
		elif path['B'] == myPubkeyData:
			path['B'] = self.stream.node.ecc
		else:
			raise ValueError('Me not included in path.')
		if path['A'] == remotePubkeyData:
			path['A'] = self.stream.remote_ecc
		elif path['B'] == remotePubkeyData:
			path['B'] = self.stream.remote_ecc
		else:
			raise ValueError('Remote not included in path.')
		self.stream.path = A2MXPath(**path)
		assert self.stream.path.isComplete
		self.stream.forward = self
		self.stream.node.new_path(self.stream.path, self.stream)

	@A2MXRequest()
	def pull(self, timestamp):
		pass

	@A2MXRequest()
	def path(self, path):
		myPubkeyData = self.stream.node.ecc.pubkeyData()
		remotePubkeyData = self.stream.remote_ecc.pubkeyData()
		if path['A'] == myPubkeyData:
			path['A'] = self.stream.node.ecc
		elif path['B'] == myPubkeyData:
			path['B'] = self.stream.node.ecc
		if path['A'] == remotePubkeyData:
			path['A'] = self.stream.remote_ecc
		elif path['B'] == remotePubkeyData:
			path['B'] = self.stream.remote_ecc
		p = A2MXPath(**path)
		assert p.isComplete

		self.stream.node.new_path(p, self.stream)

	@A2MXRequest()
	def flush(self, node, timestamp, signature):
		# this command must be signed by the originating node and invalidates all paths
		# the node is part of.
		raise NotImplemented()

	@A2MXRequest(False)
	def sendto(self, node, data):
		self.stream.node.sendto(node, data)

	@A2MXRequest(False)
	def data(self, *args, **kwargs):
		print("got data command", args, kwargs)

	@A2MXRequest(False)
	def discard(self, *args, **kwargs):
		pass

	@A2MXRequest(False)
	def sleep(self, seconds):
		ar = AsyncResult()
		def setresult():
			ar.result = True
		self.stream.node.selectloop.tadd(seconds, setresult)
		return ar

	def xxpath(self, **kwargs):
		assert 'no_URI' not in kwargs

		if kwargs['A'] == self.node.ecc.pubkeyData():
			kwargs['A'] = self.node.ecc
		elif kwargs['B'] == self.node.ecc.pubkeyData():
			kwargs['B'] = self.node.ecc
		p = A2MXPath(**kwargs)

		assert p.isComplete
		self.node.new_path(p, self.stream)
		if self.stream and self.stream.path == p and not self.stream.path.isComplete:
			self.stream.path = p
			print("incoming" if self.stream.uri == None else "outgoing", "connection up with", self.stream.remote_ecc.pubkeyHashBase58())
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
			self.stream.raw_send(r, direct=True)

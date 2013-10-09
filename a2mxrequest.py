import random

from ecc import ECC
from a2mxpath import A2MXPath, now

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
	def __init__(self, stream):
		print("init Direct")
		self.stream = stream

if config['mongodb_uri']:
	from pymongo import MongoClient
	from bson import BSON
	import datetime

	mongoclient = MongoClient(config['mongodb_uri'])
else:
	mongoclient = False

class Access():
	def __init__(self, stream):
		print("init Access")
		self.stream = stream

	@A2MXRequest()
	def Access(self, pubkey_data):
		if not mongoclient:
			return False
		self.ecc = ECC(pubkey_data=pubkey_data)
		b58hash = self.ecc.pubkeyHashBase58()
		print("Access to", b58hash)
		if b58hash not in mongoclient.database_names():
			return False
		self.db = mongoclient[b58hash]

		self.auth_timestamp = now()
		paths = self.db['path'].find()
		if paths.count() == 1:
			self.path = A2MXPath(**paths[0])
			if self.path.ecc(self.ecc.pubkeyHash()).pubkeyData() == self.ecc.pubkeyData():
				self.auth_address = False
				return (self.auth_timestamp, False)
		elif paths.count() > 1:
			print(b58hash, "check your path database")
		self.auth_address = True
		return (self.auth_timestamp, True)

	@A2MXRequest()
	def Open(self, signature):
		sigdata = BSON.encode({ 'T': self.auth_timestamp })
		if self.auth_address and self.ecc.verifyAddress(signature, sigdata):
			pass
		elif not self.auth_address and self.ecc.verify(signature, sigdata):
			pass
		else:
			raise ValueError('Login Failed')
		pathupdate = self.auth_address or self.path.timestamp > datetime.datetime.now - datetime.timedelta(days=7)
		print("Login to", self.ecc.pubkeyHashBase58(), "OK PathUpdate", pathupdate)
		if self.auth_address:
			return True
		return pathupdate

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
							self.sendCall('pull', *self.stream.node.pathlist.lastinfo())
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
	def pull(self, timestamp, rollhash):
		print("pull", timestamp, rollhash)
		pathlist = self.stream.node.pathlist
		if (timestamp, rollhash) == pathlist.lastinfo():
			return True
		try:
			index = pathlist.rollhashes[rollhash].position
		except KeyError:
			index = 0
		paths = pathlist.paths
		for i in range(index, len(paths)):
			self.sendCall('path', paths[i].data)
		return False

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


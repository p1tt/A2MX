import struct
import random
import datetime
from collections import OrderedDict
import pymongo
from bson import BSON

from config import config
from ecc import ECC

from a2mxpath import A2MXPath

class A2MXDirectException(Exception):
	pass

def A2MXDirectRequest(fn):
	fn.A2MXDirectRequest__marker__ = True
	return fn

if config['mongodb_uri'] == None:
	mongoclient = None
else:
	try:
		mongoclient = pymongo.MongoClient(config['mongodb_uri'], tz_aware=True)
	except pymongo.errors.ConnectionFailure as e:
		print("failed to connect to mongodb_uri {}: {}".format(config['mongodb_uri'], e))
		mongoclient = None

def A2MXDirectStore(node, data):
	b58node = ECC.b58(node)
	if b58node not in mongoclient.database_names():
		raise A2MXDirectException('Unknown node {}'.format(b58node))
	# FIXME check if data already in DB
	mongoclient[b58node]['inbox'].insert({ 'incoming_timestamp': datetime.datetime.now(datetime.timezone.utf), 'data': data })

def A2MXDirectPaths():
	for node in mongoclient.database_names():
		mongoclient[node]['path'].find()

class A2MXDirect():
	def __init__(self, sendfun):
		if mongoclient == None:
			raise A2MXDirectException('No MongoDB connection available.')
		self.sendfun = sendfun
		self.ecc = None
		self.auth = False

	def process(self, data):
		rid = data[:4]
		bs = BSON.decode(bytes(data[4:]), tz_aware=True)
		try:
			value = self.process_bson(bs)
		except Exception as e:
			value = None
			error = 'Exception occured: {} {}'.format(str(type(e)), str(e))
		else:
			error = None
		response = {}
		if isinstance(value, (dict, OrderedDict)):
			response = value
		else:
			if value != None:
				response = { 'data': value }
			if error != None:
				response = { 'error': error }

		if len(response):
			bv = BSON.encode(response)
			self.sendfun(rid + bv)

	def process_bson(self, bs):
		if self.ecc == None:
			self.ecc = ECC(pubkey_compressed=bs['access'])
			if self.ecc.b58_pubkey_hash() not in mongoclient.database_names():
				raise A2MXDirectException('Unknown Node {}'.format(self.ecc.b58_pubkey_hash()))
			self.db = mongoclient[self.ecc.b58_pubkey_hash()]
			print("got direct to", self.ecc.b58_pubkey_hash())
			self.auth = random.randint(0, 0xFFFFFFFF).to_bytes(4, byteorder='big')
			return { 'auth': self.auth, 'pubkey': self.ecc.pubkey_c() }
		if isinstance(self.auth, bytes):
			sigdata = self.auth + bs['authbytes']
			verify = self.ecc.verify(bs['sig'], sigdata)
			if not verify:
				raise A2MXDirectException('Not authenticated')
			self.auth = True
			return True
		if self.auth != True:
			raise A2MXDirectException('Not authenticated')

		if len(bs) > 1:
			raise A2MXDirectException('Only one command at a time supported')
		for k, v in bs.items():
			f = getattr(self, k, None)
			if getattr(f, 'A2MXDirectRequest__marker__', False) != True:
				raise A2MXDirectException('Invalid request {}'.format(k))
			return f(*v[0], **v[1])

	@A2MXDirectRequest
	def path(self, **kwargs):
		p = A2MXPath(**kwargs)
		self.db['path'].remove()
		self.db['path'].insert(p.data)
		return True

	@A2MXDirectRequest
	def find(self, query, rep):
		return [ x for x in self.db['inbox'].find(query, rep) ]

	@A2MXDirectRequest
	def save(self, doc):
		return self.db['inbox'].save(doc)


import struct
import random
import datetime
from collections import OrderedDict
import pymongo
from bson import BSON

from pyasn1.type import univ
from pyasn1.codec.der import encoder
from pyasn1.codec.der import decoder
from pyasn1.error import PyAsn1Error

from config import config
from ecc import ECC

from a2mxpath import A2MXPath

def now():
	return BSON.decode(BSON.encode({'t': datetime.datetime.now(datetime.timezone.utc)}), tz_aware=True)['t']

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
	if mongoclient == None or b58node not in mongoclient.database_names():
		raise A2MXDirectException('Unknown node {}'.format(b58node))
	# FIXME check if data already in DB
	mongoclient[b58node]['inbox'].insert({ 'incoming_timestamp': datetime.datetime.now(datetime.timezone.utf), 'data': data })

def A2MXDirectPaths():
	if mongoclient == None:
		return
	for node in mongoclient.database_names():
		if node == 'admin':
			continue
		v = mongoclient[node]['path'].find()
		if v.count() == 0:
			continue
		if v.count() != 2:
			print("invalid path spec in DB for", node)
			continue
		for p in v:
			if p:
				del p['_id']
				yield A2MXPath(**p)

class A2MXDirect():
	def __init__(self, node, sendfun):
		if mongoclient == None:
			raise A2MXDirectException('No MongoDB connection available.')
		self.node = node
		self.sendfun = sendfun
		self.ecc = None
		self.auth = False

	def process(self, data):
		rid = data[:4]
		bs = BSON.decode(bytes(data[4:]), tz_aware=True)
		try:
			value = self.process_bson(bs)
		except Exception as e:
			import traceback
			traceback.print_exc()
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
				return { 'error': 'Unknown Node {}'.format(self.ecc.b58_pubkey_hash()) }
			self.db = mongoclient[self.ecc.b58_pubkey_hash()]
			print("got direct to", self.ecc.b58_pubkey_hash())
			self.auth = now()
			return { 'auth': self.auth, 'pubkey': self.node.ecc.pubkey_c() }
		if isinstance(self.auth, datetime.datetime):
			sigdata = BSON.encode({ 'auth': self.auth })
			# OpenSSL uses ASN.1 encoded signature, try to ASN.1 decode it, if it fails assume signature is in raw format and encode it
			try:
				decoder.decode(bs['sig'])
			except PyAsn1Error:
				print("TRY TO CONVERT SIGNATURE, NON VERIFIED CODE!")
				l = len(bs['sig'])
				assert l % 2 == 0
				l = int(l / 2)
				rb = bs['sig'][:l]
				sb = bs['sig'][l:]
				r = int.from_bytes(rb, byteorder='big')
				s = int.from_bytes(sb, byteorder='big')
				rsig = encoder.encode(univ.Sequence().setComponentByPosition(0, univ.Integer(r)).setComponentByPosition(1, univ.Integer(s)))
			else:
				rsig = bs['sig']
			verify = self.ecc.verify(rsig, sigdata)
			lsig = self.node.ecc.sign(sigdata)
			if not verify:
				return { 'error': 'Not authenticated' }
			self.auth = True
			return { 'sig': lsig }
		if self.auth != True:
			return { 'error': 'Not authenticated' }

		if len(bs) > 1:
			raise A2MXDirectException('Only one command at a time supported')
		for k, v in bs.items():
			f = getattr(self, k, None)
			if getattr(f, 'A2MXDirectRequest__marker__', False) != True:
				raise A2MXDirectException('Invalid request {}'.format(k))
			args = None
			kwargs = None
			for a in v:
				if isinstance(a, (tuple, list)):
					if args == None:
						args = a
					else:
						raise A2MXDirectException('Invalid arguments')
				if isinstance(a, (dict, OrderedDict)):
					if kwargs == None:
						kwargs = a
					else:
						raise A2MXDirectException('Invalid arguments')
			args = args if args else []
			kwargs = kwargs if kwargs else {}
			return f(*args, **kwargs)

	@A2MXDirectRequest
	def path(self, **kwargs):
		p = A2MXPath(**kwargs)
		if p.endnode.pubkey_c() == self.node.ecc.pubkey_c():
			raise A2MXDirectException('Invalid path to myself')

		op = A2MXPath(self.node.ecc, self.ecc)

		self.db['path'].remove()
		self.db['path'].insert(p.data)
		self.db['path'].insert(op.data)
		self.node.new_path(p)
		self.node.new_path(op)
		return True

	@A2MXDirectRequest
	def find(self, query, rep):
		return [ x for x in self.db['inbox'].find(query, rep) ]

	@A2MXDirectRequest
	def save(self, doc):
		return self.db['inbox'].save(doc)


	@A2MXDirectRequest
	def find_routes(self, src, dst, min_hops, max_hops, max_count):
		if not src or src == b'\x00':
			src = self.node.ecc.pubkey_hash()
		routes = self.node.find_routes_from(src, dst, max_hops)
		send = []
		for route in routes:
			if len(route) < min_hops:
				continue
			send.append(route.routes)
			if len(send) >= max_count:
				break
		return send

	@A2MXDirectRequest
	def sendto(self, node, data):
		self.node.sendto(node, data)


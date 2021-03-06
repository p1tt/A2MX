import struct
import random
import datetime
from collections import OrderedDict
import pymongo
from bson import BSON

from config import config
from ecc import ECC

from a2mxpath import A2MXPath

def now():
	return BSON.decode(BSON.encode({'t': datetime.datetime.now(datetime.timezone.utc)}), tz_aware=True)['t']

class A2MXAccessException(Exception):
	pass

def A2MXAccessRequest(fn):
	fn.A2MXAccessRequest__marker__ = True
	return fn

if config['mongodb_uri'] == None:
	mongoclient = None
else:
	try:
		mongoclient = pymongo.MongoClient(config['mongodb_uri'], tz_aware=True)
	except pymongo.errors.ConnectionFailure as e:
		print("failed to connect to mongodb_uri {}: {}".format(config['mongodb_uri'], e))
		mongoclient = None

class A2MXConnectedClients:
	def __init__(self):
		self.clients = {}

	def add(self, access_instance):
		client_hash = access_instance.ecc.pubkeyHash()

		if client_hash not in self.clients:
			self.clients[client_hash] = []
		self.clients[client_hash].append(access_instance)

	def remove(self, access_instance):
		client_hash = access_instance.ecc.pubkeyHash()
		try:
			self.clients[client_hash].remove(access_instance)
		except KeyError:
			pass

	def online(self, client_hash):
		if client_hash not in self.clients:
			return []
		return self.clients[client_hash]

connected_clients = A2MXConnectedClients()

def A2MXAccessStore(node, data):
	b58node = ECC.b58(node)
	if mongoclient == None or b58node not in mongoclient.database_names():
		raise A2MXAccessException('Unknown node {}'.format(b58node))
	# FIXME check if data already in DB
	_id = mongoclient[b58node]['inbox'].insert({ 'timestamp': datetime.datetime.now(datetime.timezone.utf), 'data': data })

	rid = int(0).to_bytes(4)
	data = rid + BSON.encode({ '_id': _id })
	clients = connected_clients.online(node)
	for client in clients:
		client.sendfun(data)

def A2MXAccessPaths():
	if mongoclient == None:
		return
	for node in mongoclient.database_names():
		if node == 'admin':
			continue
		v = mongoclient[node]['path'].find()
		if v.count() == 0:
			continue
		if v.count() > 2:
			print("invalid path spec in DB for", node)
			continue
		for p in v:
			if p:
				del p['_id']
				yield A2MXPath(**p)

class A2MXAccess():
	def __init__(self, node, sendfun):
		self.node = node
		self.sendfun = sendfun
		self.ecc = None
		self.auth = False

	def disconnected(self):
		if self.auth:
			connected_clients.remove(self)
		print("A2MXAccess disconnect", self.ecc.pubkeyHashBase58() if self.ecc else "unknown", "authenticated" if self.auth == True else "not authenticated")

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
			self.ecc = ECC(pubkey_data=bs['access'])
			if self.ecc.pubkeyHash() != self.node.ecc.pubkeyHash():
				if mongoclient == None or self.ecc.pubkeyHashBase58() not in mongoclient.database_names():
					return { 'error': 'Unknown Node {}'.format(self.ecc.pubkeyHashBase58()) }
				self.db = mongoclient[self.ecc.pubkeyHashBase58()]
				print("access request to", self.ecc.pubkeyHashBase58())
			else:
				print("access to me")
			self.auth = now()
			return { 'auth': self.auth, 'pubkey': self.node.ecc.pubkeyAddress() }
		if isinstance(self.auth, datetime.datetime):
			sigdata = BSON.encode({ 'auth': self.auth })
			verify = self.ecc.verifyAddress(bs['sig'], sigdata)
			lsig = self.node.ecc.signAddress(sigdata)
			if not verify:
				return { 'error': 'Not authenticated' }

			self.auth = True
			connected_clients.add(self)

			return { 'sig': lsig }

		if self.auth != True:
			return { 'error': 'Not authenticated' }

		if len(bs) != 1:
			raise A2MXAccessException('Only one command at a time supported')
		for k, v in bs.items():
			f = getattr(self, k, None)
			if getattr(f, 'A2MXAccessRequest__marker__', False) != True:
				raise A2MXAccessException('Invalid request {}'.format(k))
			if isinstance(v, (dict, OrderedDict)):
				return f(**v)
			elif v == None:
				return f()
			raise A2MXAccessException('Invalid argument '.format(v))

	@A2MXAccessRequest
	def getpath(self):
		p = A2MXPath(self.node.ecc, self.ecc, no_URI=True)
		return p.data

	@A2MXAccessRequest
	def setpath(self, **kwargs):
		p = A2MXPath(**kwargs)
		assert p.isComplete

		self.db['path'].remove()
		self.db['path'].insert(p.data)
		self.node.new_path(p)
		return True

	@A2MXAccessRequest
	def paths(self):
		paths = [ p.data for p in self.node.paths ]
		return paths

	@A2MXAccessRequest
	def find(self, query, rep):
		return [ x for x in self.db['inbox'].find(query, rep) ]

	@A2MXAccessRequest
	def save(self, doc):
		return self.db['inbox'].save(doc)

	@A2MXAccessRequest
	def find_routes(self, src, dst, min_hops, max_hops, max_count):
		if not src or src == b'\x00':
			src = self.node.ecc.pubkeyHash()
		routes = self.node.find_routes_from(src, dst, max_hops)
		send = []
		for route in routes:
			if len(route) < min_hops:
				continue
			send.append(route.routes)
			if len(send) >= max_count:
				break
		return send

	@A2MXAccessRequest
	def sendto(self, node, data):
		return self.node.sendto(node, data)


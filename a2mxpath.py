import datetime

from bson import BSON

from ecc import ECC
from a2mxstream import InvalidDataException

def now():
	return BSON.decode(BSON.encode({'t': datetime.datetime.now(datetime.timezone.utc)}), tz_aware=True)['t']

class A2MXPath():
	def __init__(self, endnode=None, lasthop=None, signature=None, timestamp=None, axuri=None, deleted=None, delete_signature=None):
		if not isinstance(lasthop, ECC):
			try:
				self.lasthop = ECC(pubkey_compressed=lasthop)
			except Exception as e:
				print(e, lasthop)
		else:
			self.lasthop = lasthop

		if not isinstance(endnode, ECC):
			self.endnode = ECC(pubkey_compressed=endnode)
			if signature == None:
				raise ValueError()
		else:
			self.endnode = endnode

		if timestamp:
			if timestamp > datetime.datetime.now(datetime.timezone.utc):
				raise ValueError('timestamp is in the future')
			self.timestamp = timestamp
		else:
			self.timestamp = now()

		sigdata = b''.join((self.endnode.get_pubkey(), self.lasthop.get_pubkey(), self.timestamp.isoformat().encode('ascii')))
		if signature == None:
			self.signature = self.endnode.sign(sigdata)
		else:
			verify = self.endnode.verify(signature, sigdata)
			if not verify:
				raise InvalidDataException('signature failure')

			self.signature = signature

		self.stream = None
		self.axuri = axuri
		self.deleted = deleted
		self.delete_signature = delete_signature

		if self.deleted:
			if self.deleted > datetime.datetime.now(datetime.timezone.utc):
				raise ValueError('deleted timestamp is in the future')
			if self.deleted < self.timestamp:
				raise ValueError('deleted timestamp is older than timestamp')

			sigdata = b''.join((self.endnode.get_pubkey(), self.lasthop.get_pubkey(), self.timestamp.isoformat().encode('ascii'), self.deleted.isoformat().encode('ascii')))
			verify = self.lasthop.verify(delete_signature, sigdata) or self.endnode.verify(delete_signature, sigdata)
			if not verify:
				raise InvalidDataException('delete signature failure')

	def __getstate__(self):
		return { 'endnode': self.endnode.pubkey_c(), 'lasthop': self.lasthop.pubkey_c(), 'signature': self.signature, 'axuri': self.axuri, 'timestamp': self.timestamp, 'deleted': self.deleted, 'delete_signature': self.delete_signature }

	def __setstate__(self, state):
		self.endnode = ECC(pubkey_compressed=state['endnode'])
		self.lasthop = ECC(pubkey_compressed=state['lasthop'])
		self.timestamp = state['timestamp']
		self.signature = state['signature']
		self.axuri = state['axuri']
		self.deleted = state['deleted']
		self.delete_signature = state['delete_signature']
		self.stream = None

	@property
	def data(self):
		data = { 'endnode': self.endnode.pubkey_c(), 'lasthop': self.lasthop.pubkey_c(), 'signature': self.signature, 'axuri': self.axuri, 'timestamp': self.timestamp }
		if self.deleted:
			data['deleted'] = self.deleted
			data['delete_signature'] = self.delete_signature
		return data

	@property
	def endpub(self):
		return self.endnode.pubkey_hash()

	@property
	def newest_timestamp(self):
		return self.deleted or self.timestamp

	def markdelete(self):
		self.deleted = now()
		sigdata = b''.join((self.endnode.get_pubkey(), self.lasthop.get_pubkey(), self.timestamp.isoformat().encode('ascii'), self.deleted.isoformat().encode('ascii')))
		if self.lasthop.privkey:
			self.delete_signature = self.lasthop.sign(sigdata)
		elif self.endnode.privkey:
			self.delete_signature = self.endnode.sign(sigdata)
		else:
			raise ValueError('Cannot mark path as deleted without private key.')

	def __eq__(self, other):
		if not isinstance(other, A2MXPath):
			return False
		return self.endnode.get_pubkey() == other.endnode.get_pubkey() and self.lasthop.get_pubkey() == other.lasthop.get_pubkey()

	def equal(self, other):
		if not isinstance(other, A2MXPath):
			return False
		return self.data == other.data

	def is_better_than(self, other):
		if self != other:
			raise ValueError('Cannot compare paths with different nodes')
		return self.newest_timestamp > other.newest_timestamp

	def __str__(self):
		return 'Endnode: {} Lasthop: {} URI: {} Timestamp: {} Deleted: {}'.format(self.endnode.b58_pubkey_hash(), self.lasthop.b58_pubkey_hash(), self.axuri, self.timestamp.isoformat(), self.deleted.isoformat() if self.deleted else False)


import datetime

from bson import BSON

from ecc import ECC
from a2mxstream import InvalidDataException

def now():
	return BSON.decode(BSON.encode({'t': datetime.datetime.now(datetime.timezone.utc)}), tz_aware=True)['t']

class A2MXPath():
	def __init__(self, endnode=None, lasthop=None, signature=None, timestamp=None, axuri=None, deleted=None, delete_signature=None):
		if not isinstance(lasthop, ECC):
			self.lasthop = ECC()
			self.lasthop.pubkey_x, self.lasthop.pubkey_y = self.lasthop.key_uncompress(lasthop)
		else:
			self.lasthop = lasthop

		if not isinstance(endnode, ECC):
			self.endnode = ECC()
			self.endnode.pubkey_x, self.endnode.pubkey_y = self.endnode.key_uncompress(endnode)
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
		if self.deleted:
			if self.deleted > datetime.datetime.now(datetime.timezone.utc):
				raise ValueError('deleted timestamp is in the future')

			sigdata = b''.join((self.endnode.get_pubkey(), self.lasthop.get_pubkey(), self.timestamp.isoformat().encode('ascii'), self.deleted.isoformat().encode('ascii')))
			verify = self.lasthop.verify(delete_signature, sigdata) or self.endnode.verify(delete_signature, sigdata)
			if not verify:
				print("SIGDATA", self, sigdata, delete_signature)
				raise InvalidDataException('delete signature failure')
			self.delete_signature = delete_signature

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

	def __gt__(self, other):
		if not isinstance(other, A2MXPath):
			raise ValueError()
		return self.endnode.get_pubkey() > other.endnode.get_pubkey() or (self.endnode.get_pubkey() == other.endnode.get_pubkey() and self.lasthop.get_pubkey() > other.lasthop.get_pubkey())

	def __str__(self):
		return 'Endnode: {} Lasthop: {} URI: {} Timestamp: {} Deleted: {}'.format(ECC.b58(self.endnode.pubkey_hash()).decode('ascii'), ECC.b58(self.lasthop.pubkey_hash()).decode('ascii'), self.axuri, self.timestamp.isoformat(), self.deleted.isoformat() if self.deleted else False)


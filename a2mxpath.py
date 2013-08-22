import datetime

from bson import BSON

from ecc import ECC

class A2MXPath():
	def __init__(self, endnode=None, lasthop=None, signature=None, timestamp=None, axuri=None):
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

		self.timestamp = BSON.decode(BSON.encode({'t': datetime.datetime.now(datetime.timezone.utc)}), tz_aware=True)['t'] if timestamp == None else timestamp

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

	@property
	def data(self):
		return { 'endnode': self.endnode.pubkey_c(), 'lasthop': self.lasthop.pubkey_c(), 'signature': self.signature, 'axuri': self.axuri, 'timestamp': self.timestamp }

	@property
	def endpub(self):
		return self.endnode.pubkey_hash()

	def __eq__(self, other):
		if not isinstance(other, A2MXPath):
			return False
		return self.endnode.get_pubkey() == other.endnode.get_pubkey() and self.lasthop.get_pubkey() == other.lasthop.get_pubkey()

	def __gt__(self, other):
		if not isinstance(other, A2MXPath):
			raise ValueError()
		return self.endnode.get_pubkey() > other.endnode.get_pubkey() or (self.endnode.get_pubkey() == other.endnode.get_pubkey() and self.lasthop.get_pubkey() > other.lasthop.get_pubkey())

	def __str__(self):
		return 'Endnode: {} Lasthop: {} URI: {} Timestamp: {}'.format(ECC.b58(self.endnode.pubkey_hash()).decode('ascii'), ECC.b58(self.lasthop.pubkey_hash()).decode('ascii'), self.axuri, self.timestamp.isoformat())



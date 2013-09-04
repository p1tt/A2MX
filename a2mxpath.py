import datetime
from collections import OrderedDict

from bson import BSON

from ecc import ECC
from a2mxcommon import InvalidDataException

def now():
	return BSON.decode(BSON.encode({'t': datetime.datetime.now(datetime.timezone.utc)}), tz_aware=True)['t']

class A2MXPath():
	def __init__(self, A=None, B=None, T=None, SA=None, SB=None, D=None, DS=None):
		# A = node A compressed public key
		# B = node B compressed public key
		# T = timestamp
		# SA = node A signature (over A, B and T)
		# SB = node B signature (over A, B and T)
		# D = deleted timestamp
		# DS = deleted signature (over A, B, T, SA, SB and D)
		# A must always be the smaller binary value

		if not isinstance(A, ECC):
			self.__a = ECC(pubkey_compressed=A)
		else:
			self.__a = A

		if not isinstance(B, ECC):
			self.__b = ECC(pubkey_compressed=B)
		else:
			self.__b = B

		if self.__a.pubkeyCompressed() > self.__b.pubkeyCompressed():
			self.__a, self.__b = self.__b, self.__a

		if T:
			if T > datetime.datetime.now(datetime.timezone.utc):
				raise ValueError('timestamp is in the future')
			self.__t = T
		else:
			self.__t = now()

		self.__sigod = OrderedDict()
		self.__sigod['A'] = self.__a.pubkeyCompressed()
		self.__sigod['B'] = self.__b.pubkeyCompressed()
		self.__sigod['T'] = self.__t
		sigdata = BSON.encode(self.__sigod)

		self.__sa = SA
		if SA == None:
			if self.__a.hasPrivkey():
				self.__sa = self.__a.sign(sigdata)
		else:
			verify = self.__a.verify(SA, sigdata)
			if not verify:
				raise InvalidDataException('SA signature verify failed.')

		self.__sb = SB
		if SB == None:
			if self.__b.hasPrivkey():
				self.__sb = self.__b.sign(sigdata)
		else:
			verify = self.__b.verify(SB, sigdata)
			if not verify:
				raise InvalidDataException('SA signature verify failed.')

		self.__d = D
		self.__ds = DS

		if self.__d:
			if self.__d > datetime.datetime.now(datetime.timezone.utc):
				raise ValueError('deleted timestamp is in the future')
			if self.__d < self.__t:
				raise ValueError('deleted timestamp is older than timestamp')

			self.__sigod['D'] = self.__d
			sigdata = BSON.encode(self.__sigod)
			verify = self.__a.verify(self.__ds, sigdata) or self.__b.verify(self.__ds, sigdata)
			if not verify:
				raise InvalidDataException('DS signature verify failed.')

	def __getstate__(self):
		state = { 'A': self.__a.pubkey_c(), 'B': self.__b.pubkey_c(), 'T': self.__t, 'SA': self.__sa, 'SB': self.__sb }
		if self.__d:
			state['D'] = self.__d
			state['DS'] = self.__ds
		return state

	def __setstate__(self, state):
		self.__a = ECC(pubkey_compressed=state['A'])
		self.__b = ECC(pubkey_compressed=state['B'])
		self.__t = state['T']
		self.__sa = state['SA']
		self.__sb = state['SB']
		if 'D' in state:
			self.__d = state['D']
			self.__ds = state['DS']
		else:
			self.__d = None
			self.__ds = None

	@property
	def isComplete(self):
		return self.__sa != None and self.__sb != None

	@property
	def data(self):
		return self.__getstate__()

	@property
	def A(self):
		return self.__a.pubkeyCompressed()
	@property
	def AHash(self):
		return self.__a.pubkeyHash()

	@property
	def B(self):
		return self.__b.pubkeyCompressed()
	@property
	def BHash(self):
		return self.__b.pubkeyHash()

	@property
	def deleted(self):
		return self.__d

	@property
	def newest_timestamp(self):
		return self.__d or self.__t

	def markdelete(self):
		assert self.__d == None
		assert 'SA' not in self.__sigod
		assert 'SB' not in self.__sigod
		assert 'D' not in self.__sigod

		self.__sigod['SA'] = self.__sa
		self.__sigod['SB'] = self.__sb
		self.__d = now()
		self.__sigod['D'] = self.__d
		sigdata = BSON.encode(self.__sigod)
		if self.__a.hasPrivkey():
			self.__ds = self.__a.sign(sigdata)
		elif self.__b.hasPrivkey():
			self.__ds = self.__b.sign(sigdata)
		else:
			raise ValueError('Cannot mark path as deleted without private key.')

	def __eq__(self, other):
		if not isinstance(other, A2MXPath):
			return False
		return self.A == other.A and self.B == other.B

	def equal(self, other):
		if not isinstance(other, A2MXPath):
			return False
		return self.data == other.data

	def otherHash(self, otherHash):
		if otherHash == self.AHash:
			return self.BHash
		elif otherHash == self.BHash:
			return self.AHash
		raise ValueError('otherHash is neither A or B.')

	@property
	def hashes(self):
		return (self.AHash, self.BHash)

	def is_better_than(self, other):
		if self != other:
			raise ValueError('Cannot compare paths with different nodes')
		return self.newest_timestamp > other.newest_timestamp

	def __str__(self):
		return 'A: {} B: {} Timestamp: {} Deleted: {}{}'.format(self.__a.pubkeyHashBase58(), self.__b.pubkeyHashBase58(), self.__t.isoformat(), self.__d.isoformat() if self.__d else False, "" if self.isComplete else " Incomplete")


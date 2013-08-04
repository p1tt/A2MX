import pyelliptic
import hashlib

class ECC(pyelliptic.ECC):
	def __init__(self, pubkey=None, privkey=None, pubkey_x=None, pubkey_y=None):
		pyelliptic.ECC.__init__(self, curve='secp521r1', pubkey=pubkey, privkey=privkey, pubkey_x=pubkey_x, pubkey_y=pubkey_y)

	def pubkey_c(self):
		x, ybit = self.point_compress(self.pubkey_x, self.pubkey_y)
		c = bytearray(b'A')
		c += b'X' if ybit else b'x'
		c += x
		return c

	def key_uncompress(self, data):
		if chr(data[0]) != 'A': 
			raise InvalidDataException('data[0] != A')
		if chr(data[1]) == 'X':
			ybit = 1
		elif chr(data[1]) == 'x':
			ybit = 0
		else:
			raise InvalidDataException('data[1] != X|x')
		x, y = self.point_uncompress(bytes(data[2:]), ybit)
		return (x, y)

	def pubkey_hash(self):
		data = hashlib.sha512(self.get_pubkey()).digest()
		h = hashlib.new('RIPEMD160', data).digest()
		return h

	@staticmethod
	def b58(value):
		b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

		inputnum = 0
		for i in range(0, len(value)):
		        inputnum += ord(value[-i-1:len(value)-i]) * 256 ** i
		b58part = b''
		while inputnum > 0:
			b58part = b58chars[inputnum % 58:(inputnum % 58) + 1] + b58part
			inputnum //= 58
		return b58part


import pyelliptic
import hashlib

b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class ECC(pyelliptic.ECC):
	def __init__(self, pubkey=None, privkey=None, pubkey_x=None, pubkey_y=None):
		pyelliptic.ECC.__init__(self, curve='secp521r1', pubkey=pubkey, privkey=privkey, pubkey_x=pubkey_x, pubkey_y=pubkey_y)

	def pubkey_c(self):
		x, ybit = self.point_compress(self.pubkey_x, self.pubkey_y)
		c = bytearray(b'A')
		c += b'X' if ybit else b'x'
		c += (b'\0') * (66 - len(x))
		c += x
		assert len(c) == 68
		return c

	def key_uncompress(self, data):
		assert len(data) == 68
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
		inputnum = int.from_bytes(value, byteorder='big')
		b58part = b''
		while inputnum > 0:
			idx = inputnum % 58
			b58part = b58chars[idx:idx + 1] + b58part
			inputnum //= 58
		return b58part

	@staticmethod
	def b58decode(b58string):
		outputnum = 0
		for char in b58string:
			outputnum *= 58
			outputnum += b58chars.index(char)
		return outputnum.to_bytes((outputnum.bit_length() // 8) + 1, byteorder='big')

if __name__ == '__main__':
	with open("/dev/urandom","rb") as f:
		test = f.read(20083)
	b58 = ECC.b58(test)
	b58test = ECC.b58decode(b58)
	assert test == b58test

import pyelliptic
import hashlib
import base64
from pyasn1.codec.der import decoder

b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def pem2rawkeys(filename):
	def bitstring2bytes(data):      
		bits = list(data) + [0] * ((8 - len(data) % 8) % 8)
		out = bytearray()
		for i in range(0, len(bits), 8):
			byte = 0
			for b in bits[i:i+8]:
				byte <<= 1
				if b == 1:
					byte |= 0x01
				elif b == 0:
					pass
				else:
					raise ValueError()
			out += byte.to_bytes(1, byteorder='big')
		return bytes(out)

	pem = open(filename, 'r')
	inkey = False
	b64data = ''
	for line in pem:
		if line.strip() == '-----BEGIN EC PRIVATE KEY-----':
			inkey = True
		elif line.strip() == '-----END EC PRIVATE KEY-----':
			break
		elif inkey:
			b64data += line
	k = base64.b64decode(b64data)
	dk = decoder.decode(k)[0]

	# version = 1
	assert dk[0] == 1
	# curve = secp521r1
	assert str(dk[2]) == '1.3.132.0.35'
	privkey = bytes(dk[1])
	pubkey = bitstring2bytes(dk[3])

	return privkey, pubkey

class ECC(pyelliptic.ECC):
	def __init__(self, pem_keyfile=None, pubkey_x=None, pubkey_y=None, pubkey_compressed=None):
		privkey = None
		pyelliptic.ECC.__init__(self, curve='secp521r1')
		if pem_keyfile:
			privkey, pubkey = pem2rawkeys(pem_keyfile)
			pubkey_x, pubkey_y = self.oct2point(pubkey)
		elif pubkey_compressed:
			pubkey_x, pubkey_y = self.key_uncompress(pubkey_compressed)
		self._set_keys(pubkey_x, pubkey_y, privkey)

	def pubkey_c(self):
		x, ybit = self.point_compress(self.pubkey_x, self.pubkey_y)
		c = b'A'
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

	def b58_pubkey_hash(self):
		return self.b58(self.pubkey_hash()).decode('ascii')

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
		length = outputnum.bit_length() // 8
		if outputnum.bit_length() % 8 != 0:
			length += 1
		return outputnum.to_bytes(length, byteorder='big')

if __name__ == '__main__':
	with open("/dev/urandom","rb") as f:
		test = f.read(2048)
	b58 = ECC.b58(test)
	b58test = ECC.b58decode(b58)
	assert test == b58test

from a2mxcrypto import A2MXcrypto

b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class ECC():
	def __init__(self, pkcs8_der_keyfile=None, pubkey_compressed=None):
		if pkcs8_der_keyfile:
			self.crypto = A2MXcrypto(keyfilepath=pkcs8_der_keyfile.encode('UTF-8'))
		elif pubkey_compressed:
			pubkey_compressed = bytes(pubkey_compressed)
			self.crypto = A2MXcrypto(pubkey=pubkey_compressed)
		else:
			raise ValueError('Neither PKCS8 DER encoded keyfile nor public key present.')

	def pubkey_c(self):
		return self.crypto.pubkeyCompressed()

	def pubkey_hash(self):
		return self.crypto.pubkeyHash()

	def get_pubkey(self):
		return self.crypto.pubkeyCompressed()

	def b58_pubkey_hash(self):
		return self.crypto.pubkeyHashBase58().decode('ascii')

	def havePrivkey(self):
		return self.crypto.havePrivkey()

	def sign(self, message):
		message = bytes(message)
		return self.crypto.sign(message)
	def verify(self, signature, message):
		message = bytes(message)
		signature = bytes(signature)
		return self.crypto.verify(message, signature)

	def encrypt(self, message):
		message = bytes(message)
		return self.crypto.encrypt(message)
	def decrypt(self, message):
		message = bytes(message)
		return self.crypto.decrypt(message)


	@staticmethod
	def b58(value):
		inputnum = int.from_bytes(value, byteorder='big')
		b58part = b''
		while inputnum > 0:
			idx = inputnum % 58
			b58part = b58chars[idx:idx + 1] + b58part
			inputnum //= 58
		return b58part.decode('ascii')

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

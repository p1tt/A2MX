from a2mxcrypto import A2MXcrypto

b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class ECC():
	def __init__(self, keyfile=None, pubkey_data=None):
		if keyfile:
			self.crypto = A2MXcrypto(keyfile.encode('UTF-8'), b'')
		elif pubkey_data:
			pubkey_data = bytes(pubkey_data)
			self.crypto = A2MXcrypto(pubkey_data=pubkey_data)
		else:
			raise ValueError('Neither keyfile nor public key present.')

	def pubkeyData(self):
		return self.crypto.pubkeyData()

	def pubkeyHash(self):
		return self.crypto.pubkeyHash()

	def pubkeyHashBase58(self):
		return self.crypto.pubkeyHashBase58().decode('ascii')

	def pubkeyAddress(self):
		return self.crypto.pubkeyAddress()

	def hasPrivkey(self):
		return self.crypto.hasPrivkey()

	def signAddress(self, message):
		message = bytes(message)
		return self.crypto.signAddress(message)
	def verifyAddress(self, signature, message):
		message = bytes(message)
		signature = bytes(signature)
		return self.crypto.verifyAddress(message, signature)

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
		for char in b58string.encode('ascii'):
			outputnum *= 58
			outputnum += b58chars.index(char)
		length = outputnum.bit_length() // 8
		if outputnum.bit_length() % 8 != 0:
			length += 1
		return outputnum.to_bytes(length, byteorder='big')

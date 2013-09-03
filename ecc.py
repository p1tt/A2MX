from a2mxcrypto import A2MXcrypto

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


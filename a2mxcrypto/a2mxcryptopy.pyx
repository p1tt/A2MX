from libcpp.string cimport string

cdef extern from "crypto.h":
	cdef cppclass Crypto:
		Crypto(string der_keyfile_address, string der_keyfile_sign, string der_keyfile_encrypt) except +
		Crypto(string keyfilepath, string password) except +
		Crypto(string pubkey_data) except +

		bint hasPrivkey()
		string pubkeyHash()
		string pubkeyHashBase58()
		string pubkeyData()
		string pubkeyAddress()

		string signAddress(string message)
		bint verifyAddress(string message, string signature)

		string sign(string message)
		bint verify(string message, string signature)

		string encrypt(string data)
		string decrypt(string data)

cdef class A2MXcrypto:
	cdef Crypto *thisptr

	def __cinit__(self, bytes keyfilepath=None, bytes password=None, bytes pubkey_data=None, bytes der_keyfile_address=None, bytes der_keyfile_sign=None, bytes der_keyfile_encrypt=None):
		if keyfilepath != None and password != None and pubkey_data == None and der_keyfile_address == None and der_keyfile_sign == None and der_keyfile_encrypt == None:
			# encrypted keyfile
			self.thisptr = new Crypto(keyfilepath, password)
		elif keyfilepath == None and password == None and pubkey_data == None and der_keyfile_address != None and der_keyfile_sign != None and der_keyfile_encrypt != None:
			# PKCS8 DER keyfiles
			self.thisptr = new Crypto(der_keyfile_address, der_keyfile_sign, der_keyfile_encrypt)
		elif keyfilepath == None and password == None and pubkey_data != None and der_keyfile_address == None and der_keyfile_sign == None and der_keyfile_encrypt == None:
			# pubkey data
			self.thisptr = new Crypto(pubkey_data)
			return
		else:
			raise Exception("Invalid arguments")

	def __dealloc__(self):
		del self.thisptr

	def hasPrivkey(self):
		return self.thisptr.hasPrivkey()
	def pubkeyHash(self):
		return self.thisptr.pubkeyHash()
	def pubkeyHashBase58(self):
		return self.thisptr.pubkeyHashBase58()
	def pubkeyData(self):
		return self.thisptr.pubkeyData()
	def pubkeyAddress(self):
		return self.thisptr.pubkeyAddress()

	def signAddress(self, bytes message):
		return self.thisptr.signAddress(message)
	def verifyAddress(self, bytes message, bytes signature):
		return self.thisptr.verifyAddress(message, signature)

	def sign(self, bytes message):
		return self.thisptr.sign(message)
	def verify(self, bytes message, bytes signature):
		return self.thisptr.verify(message, signature)

	def encrypt(self, bytes data):
		return self.thisptr.encrypt(data)
	def decrypt(self, bytes data):
		return self.thisptr.decrypt(data)

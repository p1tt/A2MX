#cimport cython
from libcpp.string cimport string

cdef extern from "crypto.h":
	cdef cppclass Crypto:
		Crypto(string a, string b, int mode) except +
		Crypto(string pubkey) except +

		bint hasPrivkey()
		string pubkeyHash()
		string pubkeyHashBase58()
		string pubkeyCompressed()

		string sign(string message)
		bint verify(string message, string signature)

		string encrypt(string data)
		string decrypt(string data)

cdef class A2MXcrypto:
	cdef Crypto *thisptr

	def __cinit__(self, bytes keyfilepath=None, bytes password=None, bytes pubkey=None, bytes der_keyfile_sign=None, bytes der_keyfile_encrypt=None):
		cdef int mode
		cdef bytes a
		cdef bytes b

		if keyfilepath == None and password != None and pubkey == None and der_keyfile_sign == None and der_keyfile_encrypt == None:
			mode = 0
			a = b''
			b = password
		elif keyfilepath != None and password != None and pubkey == None and der_keyfile_sign == None and der_keyfile_encrypt == None:
			mode = 1
			a = keyfilepath
			b = password
		elif keyfilepath == None and password == None and pubkey == None and der_keyfile_sign != None and der_keyfile_encrypt != None:
			mode = 2
			a = der_keyfile_sign
			b = der_keyfile_encrypt
		elif keyfilepath == None and password == None and pubkey != None and der_keyfile_sign == None and der_keyfile_encrypt == None:
			self.thisptr = new Crypto(pubkey)
			return
		else:
			raise Exception("Invalid arguments")
		self.thisptr = new Crypto(a, b, mode)

	def __dealloc__(self):
		del self.thisptr

	def hasPrivkey(self):
		return self.thisptr.hasPrivkey()
	def pubkeyHash(self):
		return self.thisptr.pubkeyHash()
	def pubkeyHashBase58(self):
		return self.thisptr.pubkeyHashBase58()
	def pubkeyCompressed(self):
		return self.thisptr.pubkeyCompressed()

	def sign(self, bytes message):
		return self.thisptr.sign(message)
	def verify(self, bytes message, bytes signature):
		return self.thisptr.verify(message, signature)

	def encrypt(self, bytes data):
		return self.thisptr.encrypt(data)
	def decrypt(self, bytes data):
		return self.thisptr.decrypt(data)

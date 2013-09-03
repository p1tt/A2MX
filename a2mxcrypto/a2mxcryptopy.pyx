#cimport cython
from libcpp.string cimport string

cdef extern from "crypto.h":
	cdef cppclass Crypto:
		Crypto(string keyfilepath, string password, int mode) except +
		Crypto(string pubkey) except +

		bint havePrivkey()
		string pubkeyHash()
		string pubkeyHashBase58()
		string pubkeyCompressed()

		string sign(string message)
		bint verify(string message, string signature)

		string encrypt(string data)
		string decrypt(string data)

cdef class A2MXcrypto:
	cdef Crypto *thisptr

	def __cinit__(self, bytes keyfilepath=None, bytes password=None, bytes pubkey=None):
		cdef int mode
		if keyfilepath == None and password != None:
			mode = 0
		elif keyfilepath != None and password != None:
			mode = 1
		elif keyfilepath != None and password == None:
			mode = 2
		elif pubkey != None:
			self.thisptr = new Crypto(pubkey)
			return
		else:
			raise Exception("Invalid arguments")
		if password == None:
			password = b''
		if keyfilepath == None:
			keyfilepath = b''
		self.thisptr = new Crypto(keyfilepath, password, mode)

	def __dealloc__(self):
		del self.thisptr

	def havePrivkey(self):
		return self.thisptr.havePrivkey()
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

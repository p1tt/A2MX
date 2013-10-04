from libcpp.string cimport string

cdef extern from "crypto.h":
	cdef cppclass Crypto:
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

cdef extern from "crypto.h" namespace "Crypto":
	void createNewKeyFile(string path, string password)

cdef class A2MXcrypto:
	cdef Crypto *thisptr

	def __cinit__(self, str keyfilepath=None, str password=None, bytes pubkey_data=None):
		if keyfilepath != None:
			if password == None:
				password = ''
			self.thisptr = new Crypto(keyfilepath.encode('UTF-8'), password.encode('UTF-8'))
		elif keyfilepath == None and password == None and pubkey_data != None:
			self.thisptr = new Crypto(pubkey_data)
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

	@staticmethod
	def createNewKeyFile(bytes path, bytes password):
		createNewKeyFile(path, password)

cdef extern from "a2mxpow.h":
	cdef cppclass A2MXpow nogil:
		A2MXpow() except +
		int calculate(unsigned char* messagehash, int messagesize, double difficulty)
		bint check(unsigned char* messagehash, int messagesize, double difficulty, unsigned long long nonce)

cdef class ProofOfWork:
	cdef A2MXpow *thisptr

	def __cinit__(self):
		self.thisptr = new A2MXpow()

	def __dealloc__(self):
		del self.thisptr

	def calculate(self, bytes messagehash, int messagesize, double difficulty):
		if len(messagehash) != 256 / 8:
			raise ValueError('messagehash is not 256 bits long.')
		cdef unsigned char* mh = messagehash
		cdef int ms = messagesize
		cdef double d = difficulty
		cdef unsigned long long nonce
		with nogil:
			nonce = self.thisptr.calculate(mh, ms, d)
		return nonce

	def check(self, bytes messagehash, int messagesize, double difficulty, unsigned long long nonce):
		if len(messagehash) != 256 / 8:
			raise ValueError('messagehash is not 256 bits long.')
		cdef unsigned char* mh = messagehash
		cdef int ms = messagesize
		cdef double d = difficulty
		with nogil:
			ok = self.thisptr.check(mh, ms, d, nonce)
		return ok


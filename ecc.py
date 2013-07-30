import pyelliptic

class ECC(pyelliptic.ECC):
	def __init__(self, pubkey=None, privkey=None, pubkey_x=None, pubkey_y=None):
		pyelliptic.ECC.__init__(self, curve='secp521r1', pubkey=pubkey, privkey=privkey, pubkey_x=pubkey_x, pubkey_y=pubkey_y)


from xmlrpc.server import SimpleXMLRPCServer

from ecc import ECC

class A2MXClientInterface():
	def __init__(self, node):
		self.node = node

	def find_routes(self, destination):
		try:
			return self._find_routes(destination)
		except Exception as e:
			import traceback
			traceback.print_exc()

	def _find_routes(self, destination):
		dst = ECC.b58decode(destination.encode('ascii'))
		if dst not in self.node.paths:
			return False
		me = self.node.ecc.pubkey_hash()
		pathlist = self.node.paths[dst]
		if len(pathlist) == 0:
			return False

		def find_path(pathlist, thispath=None):
			if thispath == None:
				thispath = [dst]
			for path in pathlist:
				lasthop = path.lasthop.pubkey_hash()
				if lasthop == me:
					ytp = thispath[:]
					ytp.append(lasthop)
					yield ytp
					continue
				if lasthop == dst:
					continue
				if lasthop in thispath:
					continue
				tp = thispath[:]
				tp.append(lasthop)
				for p in find_path(self.node.paths[lasthop], tp):
					yield p

		return [ p for p in find_path(pathlist) ]

		pi = 0
		for p in find_path(pathlist):
			s = 'path {}:'.format(pi)
			for hop in p:
				s+= ' ' + ECC.b58(hop).decode('ascii')
			print(s)
			pi += 1

		return True

class A2MXXMLRPCServer(SimpleXMLRPCServer):
	def __init__(self, node, bind):
		SimpleXMLRPCServer.__init__(self, bind, logRequests=False)
		self.register_introspection_functions()
		self.register_instance(A2MXClientInterface(node))

	def select_r(self):
		self.handle_request()
	def select_w(self):
		assert False
	def select_e(self):
		assert False

	def finish(self):
		pass

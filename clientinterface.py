from xmlrpc.server import SimpleXMLRPCServer

from ecc import ECC

class A2MXClientInterface():
	def __init__(self, node):
		self.node = node

	def find_routes(self, destination, maxroutes=None, minhops=None, maxhops=None):
		routes = []
		maxroutes = None if maxroutes == None or maxroutes == '-' else int(maxroutes)
		minhops = None if minhops == None or minhops == '-' else int(minhops)
		maxhops = None if maxhops == None or maxhops == '-' else int(maxhops)
		try:
			for route in self._find_routes(destination, maxhops):
				if minhops != None and len(route) < minhops:
					continue
				routes.append(route)
				if maxroutes != None and len(routes) >= maxroutes:
					break
		except Exception as e:
			import traceback
			traceback.print_exc()
		return routes

	def _find_routes(self, destination, maxhops):
		dst = ECC.b58decode(destination.encode('ascii'))
		if dst not in self.node.paths:
			return []
		me = self.node.ecc.pubkey_hash()
		pathlist = self.node.paths[dst]
		if len(pathlist) == 0:
			return []

		def find_path(pathlist, thispath=None, step=1):
			if maxhops != None and step >= maxhops:
				return
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
				for p in find_path(self.node.paths[lasthop], tp, step+1):
					yield p

		return find_path(pathlist)

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

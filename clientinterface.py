from xmlrpc.server import SimpleXMLRPCServer
import hashlib

from ecc import ECC

class A2MXClientInterface():
	def __init__(self, node):
		self.node = node

	def find_routes(self, destination, maxroutes=None, minhops=None, maxhops=None):
		try:
			routes = []
			maxroutes = None if maxroutes == None or maxroutes == '-' else int(maxroutes)
			minhops = None if minhops == None or minhops == '-' else int(minhops)
			maxhops = None if maxhops == None or maxhops == '-' else int(maxhops)

			me = self.node.ecc.pubkey_hash()
			destination = ECC.b58decode(destination.encode('ascii'))

			for route in self._find_routes_from(me, destination, maxhops):
				if minhops != None and len(route) < minhops:
					continue
				routes.append(route)
				if maxroutes != None and len(routes) >= maxroutes:
					break
		except Exception as e:
			import traceback
			traceback.print_exc()
		return routes

	def find_routes_from(self, source, destination, maxroutes=None, minhops=None, maxhops=None):
		try:
			routes = []
			maxroutes = None if maxroutes == None or maxroutes == '-' else int(maxroutes)
			minhops = None if minhops == None or minhops == '-' else int(minhops)
			maxhops = None if maxhops == None or maxhops == '-' else int(maxhops)

			source = ECC.b58decode(source.encode('ascii'))
			destination = ECC.b58decode(destination.encode('ascii'))

			for route in self._find_routes_from(source, destination, maxhops):
				if minhops != None and len(route) < minhops:
					continue
				routes.append(route)
				if maxroutes != None and len(routes) >= maxroutes:
					break
		except Exception as e:
			import traceback
			traceback.print_exc()
		return routes

	def _find_routes_from(self, src, dst, maxhops):
		if dst not in self.node.paths:
			return []
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
				if lasthop == src:
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

	def dump_paths(self):
		try:
			return self._dump_paths()
		except Exception as e:
			import traceback
			traceback.print_exc()

	def _dump_paths(self):
		print("dump_paths")
		l = sorted(self.node.paths.keys())
		s = b''
		for k in l:
			v = self.node.paths[k]
			print(ECC.b58(k).decode('ascii'))
			s += k
			for p in v:
				s += p.endpub + p.lasthop.pubkey_hash()
				print("  ", p)
		print("SHA256", hashlib.sha256(s).hexdigest())
		return 0

	def dump_streams(self):
		print("dump_streams")
		for stream in self.node.streams:
			print(stream)
		print("Update stream", self.node.update_stream)

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

	def shutdown(self):
		pass

#!/usr/bin/env python3

import sys
import atexit
import signal
import socket
import select
import os
import datetime
import random
import pickle
from operator import attrgetter

from ecc import ECC

from config import config
from a2mxstream import A2MXStream
import a2mxdirect

class Unbuffered:
	def __init__(self, stream):
		self.stream = stream
	def write(self, data):
		self.stream.write(data)
		self.stream.flush()
	def __getattr__(self, attr):
		return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

class A2MXServer():
	def __init__(self, node, bind):
		self.node = node

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setblocking(0)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(bind)
		print("bound to", bind, config['publish_axuri'])
		self.sock.listen(5)
		self.node.add(self)

	def fileno(self):
		return self.sock.fileno()

	def select_r(self):
		sock, addr = self.sock.accept()
		if len(self.node.streams) >= config['max_connections']:
			print("maximum connection count reached, rejecting new connection from", addr)
			sock.shutdown(socket.SHUT_RDWR)
			sock.close()
			return
		A2MXStream(self.node, sock=sock)

	def select_w(self):
		assert False
	def select_e(self):
		assert False

	def shutdown(self):
		self.sock.close()
		self.node.remove(self)

class A2MXRoute():
	def __init__(self, routes):
		self.routes = routes

	def __len__(self):
		return len(self.routes)

	def __str__(self):
		s = 'A2MXRoute'
		for r in self.routes:
			s += ' ' + ECC.b58(r).decode('ascii')
		return s

class A2MXNode():
	def __init__(self, selectloop):
		self.selectloop = selectloop

		self.paths = []
		try:
			with open(config['paths.db'], 'rb') as f:
				try:
					self.paths = pickle.load(f)
				except EOFError:
					pass
		except FileNotFoundError:
			pass

		self.nodes = {}
		for path in self.paths:
			self.update_nodes(path)

		self.streams = []
		self.connected_nodes = {}
		self.axuris = {}

		self.ecc = ECC(pem_keyfile=config['key.pem'])

		mypub = self.ecc.b58_pubkey_hash()
		if sys.stdout.isatty():
			cwd = os.getcwd().rsplit('/', 1)[1]
			sys.stdout.write("\x1b]2;{}: {}\x07".format(cwd, mypub))
		print("I am", mypub)

		for path in a2mxdirect.A2MXDirectPaths():
			self.new_path(path)

		self.selectloop.tadd(random.randint(5, 15), self.find_new_peers)

	def savepaths(self):
		with open(config['paths.db'], 'wb') as f:
			pickle.dump(self.paths, f)

	def add(self, selectable):
		self.selectloop.add(selectable)
	def remove(self, selectable):
		self.selectloop.remove(selectable)
	def wadd(self, selectable):
		self.selectloop.wadd(selectable)
	def wremove(self, selectable):
		self.selectloop.wremove(selectable)

	def add_stream(self, stream):
		if stream.remote_ecc.pubkey_c() in self.connected_nodes:
			return False
		assert stream not in self.streams
		self.streams.append(stream)
		self.connected_nodes[stream.remote_ecc.pubkey_c()] = stream

		return True

	def del_stream(self, stream):
		if stream not in self.streams:
			return
		self.streams.remove(stream)
		assert stream.remote_ecc.pubkey_c() in self.connected_nodes and self.connected_nodes[stream.remote_ecc.pubkey_c()] == stream
		del self.connected_nodes[stream.remote_ecc.pubkey_c()]

		if stream.incoming_path:
			self.del_path(stream.incoming_path)
		if stream.outgoing_path:
			self.del_path(stream.outgoing_path)
		else:
			print("NO OUTGOING?! :-(")

	def new_path(self, path):
		if path in self.paths:
			oldindex = self.paths.index(path)
			oldpath = self.paths[oldindex]
			if path is oldpath:
				del self.paths[oldindex]
			elif path.equal(oldpath):
				print("ignoring known path from {}\n ".format(path.stream.remote_ecc.b58_pubkey_hash() if path.stream else 'myself'), path)
				return
			elif path.is_better_than(oldpath):
				print("updating path\n  old:", oldpath, "\n  new:", path)
				del self.paths[oldindex]
			else:
				print("ignoring path with older timestamp as known path\n  old:", oldpath, "\n  new:", path)
				return
		else:
			print("new path\n ", path)

		self.paths.append(path)
		try:
			lastpath = self.paths[-2]
		except IndexError:
			return
		if path.newest_timestamp < lastpath.newest_timestamp:
			self.paths.sort(key=attrgetter('newest_timestamp'))

		self.update_nodes(path)

		for stream in self.streams:
			if stream == path.stream:
				continue
			stream.send(stream.request('path', **path.data))

	def del_path(self, path):
		path.markdelete()
		self.new_path(path)

	def update_nodes(self, path):
		if path.endpub not in self.nodes:
			self.nodes[path.endpub] = []
		nl = self.nodes[path.endpub]
		if path in nl:
			nl.remove(path)
		nl.append(path)

	def sendto(self, node, data):
		if node not in self.nodes:
			try:
				a2mxdirect.A2MXDirectStore(node, data)
				print("stored data for {}".format(ECC.b58(node)))
			except A2MXDirectException:
				print("cannot send to node {}".format(ECC.b58(node)))
			return
		self.nodes[node].raw_send(data)

	def find_new_peers(self):
		self.selectloop.tadd(random.randint(5, 15), self.find_new_peers)

		if len(self.streams) >= config['connections']:
			return

		axuris = []

		for path in self.paths:
			if path.axuri != None and not path.deleted and path.endpub != self.ecc.pubkey_hash() and path.axuri not in axuris:
				already_connected = False
				for stream in self.streams:
					if stream.remote_ecc.pubkey_hash() == path.endnode.pubkey_hash():
						already_connected = True
						break
				if not already_connected:
					axuris.append((path.axuri, path.endnode.b58_pubkey_hash()))

		try:
			axuri = random.choice(axuris)
		except IndexError:
			return
		A2MXStream(self, uri=axuri[0], pubkey_hash=axuri[1])

	def find_routes_from(self, src, dst, maxhops=None):
		if dst not in self.nodes:
			return []
		pathlist = self.nodes[dst]
		if len(pathlist) == 0:
			return []
		dst_pubc = pathlist[0].endnode.pubkey_c()

		def find_path(pathlist, thispath=None, step=1):
			if maxhops != None and step >= maxhops:
				return
			if thispath == None:
				thispath = [dst_pubc]
			for path in pathlist:
				if path.deleted:
					continue
				lasthop = path.lasthop.pubkey_hash()
				lasthop_pubc = path.lasthop.pubkey_c()
				if lasthop == src:
					ytp = thispath[:]
					ytp.append(lasthop_pubc)
					yield A2MXRoute(ytp)
					continue
				if lasthop == dst:
					continue
				if lasthop_pubc in thispath:
					continue
				tp = thispath[:]
				tp.append(lasthop_pubc)
				for p in find_path(self.nodes[lasthop], tp, step+1):
					yield p
		return find_path(pathlist)

	def shortest_route(self, src, dst):
		try:
			routes = [ x for x in self.find_routes_from(src, dst) ]
		except KeyError:
			return A2MXRoute([])
		if len(routes) == 0:
			return A2MXRoute([])
		return min(routes, key=len)

class SelectLoop():
	def __init__(self):
		self.rlist = []
		self.wlist = []
		self.tlist = []

	def add(self, selectable):
		assert selectable not in self.rlist
		self.rlist.append(selectable)
	def remove(self, selectable):
		try:
			self.rlist.remove(selectable)
		except ValueError:
			pass
	def wadd(self, selectable):
		assert selectable not in self.wlist
		self.wlist.append(selectable)
	def wremove(self, selectable):
		try:
			self.wlist.remove(selectable)
		except ValueError:
			pass
	def tadd(self, seconds, call, *args, **kwargs):
		callat = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
		self.tlist.append((callat, call, args, kwargs))
		self.tlist.sort(key=lambda tup: tup[0])

	def select(self):
		timeout = None
		if len(self.tlist) > 0:
			timeout = (self.tlist[0][0] - datetime.datetime.now()).total_seconds()
			if timeout < 0:
				timeout = 0
		try:
			r, w, e = select.select(self.rlist, self.wlist, self.rlist, timeout)
		except InterruptedError:
			return
		for sock in e:
			sock.select_e()
		for sock in w:
			sock.select_w()
		for sock in r:
			sock.select_r()
		while len(self.tlist) > 0:
			if self.tlist[0][0] <= datetime.datetime.now():
				self.tlist[0][1](*self.tlist[0][2], **self.tlist[0][3])
				del self.tlist[0]
			else:
				break

	def shutdown(self):
		for sock in set(self.rlist + self.wlist):
			sock.shutdown()

selectloop = SelectLoop()

node = A2MXNode(selectloop)

def shutdown(sig, frm):
	node.savepaths()
	sys.exit(0)
def save(sig, frm):
	node.savepaths()
signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGHUP, save)

atexit.register(node.savepaths)

for bind in config['bind']:
	A2MXServer(node, bind)

for uri in config['targets']:
	A2MXStream(node, uri=uri)

try:
	while True:
		selectloop.select()
except KeyboardInterrupt:
#	selectloop.shutdown()
	pass


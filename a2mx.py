#!/usr/bin/env python3

import sys
import socket
import select
import os
import datetime
import random

from ecc import ECC

from config import config
from a2mxstream import A2MXStream

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

		self.paths = {}
		self.streams = []
		self.update_stream = None
		try:
			with open('.a2mx/priv', 'rb') as f:
				privkey = f.read()
			with open('.a2mx/pub', 'rb') as f:
				pubkey = f.read()
		except FileNotFoundError:
			privkey = None
			pubkey = None
		self.ecc = ECC(privkey=privkey, pubkey=pubkey)
		if privkey == None:
			os.umask(63)	# 0700
			try:
				os.mkdir('.a2mx')
			except FileExistsError:
				pass
			with open('.a2mx/priv', 'wb') as f:
				f.write(self.ecc.get_privkey())
			with open('.a2mx/pub', 'wb') as f:
				f.write(self.ecc.get_pubkey())
		mypub = ECC.b58(self.ecc.pubkey_hash()).decode('ascii')
		if sys.stdout.isatty():
			cwd = os.getcwd().rsplit('/', 1)[1]
			sys.stdout.write("\x1b]2;{}: {}\x07".format(cwd, mypub))
		print("I am", mypub)
		self.selectloop.tadd(random.randint(5, 15), self.find_new_peers)

	def add(self, selectable):
		self.selectloop.add(selectable)
	def remove(self, selectable):
		self.selectloop.remove(selectable)
	def wadd(self, selectable):
		self.selectloop.wadd(selectable)
	def wremove(self, selectable):
		self.selectloop.wremove(selectable)

	def add_stream(self, stream):
		assert stream not in self.streams
		self.streams.append(stream)

		if self.update_stream == None:
			self.update_stream = stream
			r = stream.request('pull', datetime.datetime.min)
			sr = stream.request('data', 'hello')
			r = stream.request('sleep', 10, request=r, next=sr)
			stream.send(r)

	def del_stream(self, stream):
		if stream not in self.streams:
			return
		self.streams.remove(stream)
		if stream == self.update_stream:
			if len(self.streams) == 0:
				self.update_stream = None
				print("no streams left for updates")
			else:
				self.update_stream = self.streams[0]
		self.del_path(stream.incoming_path)
		if stream.outgoing_path:
			self.del_path(stream.outgoing_path)

	def new_path(self, path):
		endpub = path.endpub
		if endpub not in self.paths:
			self.paths[endpub] = []
			print("node discovered", ECC.b58(path.endnode.pubkey_hash()).decode('ascii'))
		pathlist = self.paths[endpub]

		if path not in pathlist:
			pathlist.append(path)
			pathlist.sort()
		else:
			index = pathlist.index(path)
			oldpath = pathlist[index]

			if path.deleted and path.deleted >= oldpath.timestamp:
				pass
			elif path.timestamp <= oldpath.timestamp:
				print("path", path, "known. ignoring.")
				return
			else:
				if oldpath.deleted and path.timestamp < oldpath.deleted:
					print("ignoring path with older timestamp than deleted")
					return
			print("updating path", path)
			pathlist[index] = path

		for ostream in self.streams:
			if ostream == path.stream or (not ostream.send_updates and ostream != self.update_stream):
				continue
			print("sending", path, "to", ECC.b58(ostream.remote_ecc.pubkey_hash()).decode('ascii'))
			ostream.send(ostream.request('path', **path.data))

	def del_path(self, path):
		path.markdelete()
		self.new_path(path)

	def find_new_peers(self):
		self.selectloop.tadd(random.randint(5, 15), self.find_new_peers)

		if len(self.streams) >= config['connections']:
			return

		for pathlist in self.paths.values():
			if len(pathlist) == 0:
				continue
			path = pathlist[0]

			if path.axuri != None and not path.deleted and path.endpub != self.ecc.pubkey_hash():
				already_connected = False
				for stream in self.streams:
					if stream.remote_ecc.pubkey_hash() == path.endnode.pubkey_hash():
						already_connected = True
						break
				if not already_connected:
					A2MXStream(self, uri=path.axuri)
					break

	def find_routes_from(self, src, dst, maxhops=None):
		if dst not in self.paths:
			return []
		pathlist = self.paths[dst]
		if len(pathlist) == 0:
			return []

		def find_path(pathlist, thispath=None, step=1):
			if maxhops != None and step >= maxhops:
				return
			if thispath == None:
				thispath = [dst]
			for path in pathlist:
				if path.deleted:
					continue
				lasthop = path.lasthop.pubkey_hash()
				if lasthop == src:
					ytp = thispath[:]
					ytp.append(lasthop)
					yield A2MXRoute(ytp)
					continue
				if lasthop == dst:
					continue
				if lasthop in thispath:
					continue
				tp = thispath[:]
				tp.append(lasthop)
				for p in find_path(self.paths[lasthop], tp, step+1):
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
		r, w, e = select.select(self.rlist, self.wlist, self.rlist, timeout)
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
for bind in config['bind']:
	A2MXServer(node, bind)

for uri in config['targets']:
	A2MXStream(node, uri=uri)

if config['client_interface']:
	from clientinterface import A2MXXMLRPCServer
	xmlrpcserver = A2MXXMLRPCServer(node, config['client_interface'])
	selectloop.add(xmlrpcserver)

try:
	while True:
		selectloop.select()
except KeyboardInterrupt:
#	selectloop.shutdown()
	pass


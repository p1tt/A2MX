#!/usr/bin/env python3

import os
import sys
import socket
import ssl
import datetime
import struct
import random
from collections import OrderedDict
from bson import BSON

from ecc import ECC
from a2mxpath import A2MXPath

class RemoteException(Exception):
	pass

keyfile = sys.argv[1]
hostport = sys.argv[2].split(':')
if len(hostport) == 1:
	host = hostport[0]
	port = 0xA22
elif len(hostport) == 2:
	host = hostport[0]
	port = int(hostport[1])
else:
	raise ValueError('invalid arguments')

ecc = ECC(pem_keyfile=keyfile)
print("I am", ecc.b58_pubkey_hash())

def SSL(sock):
	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
	context.verify_mode = ssl.CERT_NONE
	context.set_ecdh_curve('secp521r1')
	context.options = ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
	context.set_ciphers('ECDHE-ECDSA-AES256-SHA')
	return context.wrap_socket(sock, do_handshake_on_connect=True)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
sock.connect((host, port))
sock = SSL(sock)

def request(fn, *args, **kwargs):
	return { fn: (args, kwargs) }
	a = OrderedDict()
	a[fn] = (args, kwargs)
	return a

def send(request):
	rid = random.randint(0, 0xFFFFFF).to_bytes(4, byteorder='big')
	data = BSON.encode(request)
	s = rid + data
	p = struct.pack('>BH', 1, len(s))
	sock.sendall(p + s)

	data = bytearray()
	exp_len = 3
	got_len = False
	while True:
		data += sock.recv(4096)
		if len(data) < exp_len:
			continue
		if not got_len:
			d, l = struct.unpack('>BH', data[:3])
			assert d == 1
			data = data[3:]
			got_len = True
		if len(data) < l:
			continue
		assert l > 4
		assert len(data) == l
		got_rid = data[:4]
		assert got_rid == rid
		bs = BSON.decode(bytes(data[4:]), tz_aware=True)
		if 'error' in bs:
			raise RemoteException(bs['error'])
		if len(bs) == 1 and 'data' in bs:
			return bs['data']
		return bs

r = send({'access': ecc.pubkey_c()})
auth = r['auth']
pubkey = r['pubkey']
remote_ecc = ECC(pubkey_compressed=pubkey)

authbytes = os.urandom(32)
sig = ecc.sign(auth + authbytes)
auth = send({'auth': authbytes, 'sig': sig})
assert auth == True

if remote_ecc.pubkey_c() != ecc.pubkey_c():
	path = A2MXPath(ecc, remote_ecc)
	pathup = send(request('path', **path.data))
	print("path update", pathup)

docs = send(request('find', { 'timestamp': { '$gt': datetime.datetime.min }}, {}))
for doc in docs:
	print(send(request('find', doc, None)))


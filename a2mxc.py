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
from config import config

class RemoteException(Exception):
	pass

if len(sys.argv) == 1:
	host = 'localhost'
	port = config['bind'][0][1]
else:
	hostport = sys.argv[1].split(':')
	if len(hostport) == 1:
		host = hostport[0]
		port = 0xA22
	elif len(hostport) == 2:
		host = hostport[0]
		port = int(hostport[1])
	else:
		raise ValueError('invalid arguments')

ecc = ECC(pkcs8_der_keyfile_address=config['address.pkcs8.der'], pkcs8_der_keyfile_sign=config['sign.pkcs8.der'], pkcs8_der_keyfile_encrypt=config['encrypt.pkcs8.der'])
print("I am", ecc.pubkeyHashBase58())

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
	p = struct.pack('>BLH', 2, random.randint(0, 0xFFFFFFFF), len(s))
	sock.sendall(p + s)

	data = bytearray()
	exp_len = 7
	got_len = False
	while True:
		data += sock.recv(4096)
		if len(data) < exp_len:
			continue
		if not got_len:
			d, r, l = struct.unpack('>BLH', data[:7])
			assert d == 2
			data = data[7:]
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

r = send({'access': ecc.pubkeyData()})
rauth = r['auth']
pubkey = r['pubkey']
remote_ecc = ECC(pubkey_data=pubkey)

sigdata = BSON.encode({ 'auth': rauth })
sig = ecc.signAddress(sigdata)
auth = send({'sig': sig})
assert 'sig' in auth
peer_verified = remote_ecc.verifyAddress(auth['sig'], sigdata)
assert peer_verified == True

#docs = send(request('find', { 'timestamp': { '$gt': datetime.datetime.min }}, {}))
#for doc in docs:
#	print(send(request('find', doc, None)))
paths = send(request('paths'))
for path in paths:
	p = A2MXPath(**path)
	print(p)

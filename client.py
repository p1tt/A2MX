#!/usr/bin/env python3

import xmlrpc.client
import sys

from ecc import ECC

s = xmlrpc.client.ServerProxy('http://localhost:6666')
#routes = s.find_routes('KfjCe3Kd2hi7jcSsKpF1WX3pQV3', 3, 2, 5)
routes = s.find_routes(*sys.argv[1:])
ri = 0
for route in routes:
	s = 'route {}:'.format(ri)
	for hop in route:
		s += ' ' + ECC.b58(hop.data).decode('ascii')
	print(s)
	ri += 1		

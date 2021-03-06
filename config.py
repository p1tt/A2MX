config = {
	'tls.cert.pem': '.a2mx/tls.cert.pem',
	'tls.key.pem': '.a2mx/tls.key.pem',
	'dh.pem': '.a2mx/dh.pem',
	'keyfile': '.a2mx/keyfile',
	'paths.db': '.a2mx/paths.db',
	'bind': [ ('', 2594) ],
	'publish_axuri': None,
	'targets': [],
	'connections': 5,
	'max_connections': 10,
	'mongodb_uri': None,
	'MaxSize': 1024*1024*20,
	'PB': 3.0,
	'PF': 2.0,
	'PD': 1.0,
}

try:
	with open('.a2mx/config', 'r') as c:
		code = c.read()
except FileNotFoundError:
	pass
else:
	code = compile(code, '.a2mx/config', 'exec')
	eval(code, { '__builtins__': {}}, config)

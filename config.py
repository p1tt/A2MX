config = {
	'tls.cert.pem': '.a2mx/tls.cert.pem',
	'tls.key.pem': '.a2mx/tls.key.pem',
	'sign.pkcs8.der': '.a2mx/sign.pkcs8.der',
	'encrypt.pkcs8.der': '.a2mx/encrypt.pkcs8.der',
	'paths.db': '.a2mx/paths.db',
	'bind': [ ('', 2594) ],
	'publish_axuri': None,
	'targets': [],
	'connections': 5,
	'max_connections': 10,
	'mongodb_uri': None
}

try:
	with open('.a2mx/config', 'r') as c:
		code = c.read()
except FileNotFoundError:
	pass
else:
	code = compile(code, '.a2mx/config', 'exec')
	eval(code, { '__builtins__': {}}, config)

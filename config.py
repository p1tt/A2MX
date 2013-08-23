config = {
	'cert.pem': '.a2mx/cert.pem',
	'key.pem': '.a2mx/key.pem',
	'bind': [ ('', 2594) ],
	'publish_axuri': None,
	'targets': [],
	'client_interface': False,
	'connections': 5,
	'max_connections': 10,
}

try:
	with open('.a2mx/config', 'r') as c:
		code = c.read()
except FileNotFoundError:
	pass
else:
	code = compile(code, '.a2mx/config', 'exec')
	eval(code, { '__builtins__': {}}, config)

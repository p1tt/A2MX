config = {
	'bind': ('', 2594),
	'publish_axuri': None,
	'targets': []
}

try:
	with open('.a2mx/config', 'r') as c:
		code = c.read()
except FileNotFoundError:
	pass
else:
	code = compile(code, '.a2mx/config', 'exec')
	eval(code, { '__builtins__': {}}, config)

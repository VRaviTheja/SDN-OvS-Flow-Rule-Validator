import pytricia

pyt = pytricia.PyTricia()

pyt["10.0.0.0/8"] = 'a'
pyt["10.1.0.0/16"] = 'b'
pyt["10.0.0.0/8"] = 'chhg'
form = list(pyt)
print form
for x in form:
	print pyt.get(x)



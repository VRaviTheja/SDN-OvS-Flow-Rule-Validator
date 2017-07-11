import ipaddress
n1 = ipaddress.ip_network('10.5.0.0/16')
n2 = ipaddress.ip_network('10.5.50.5/32')
n3 = list(n1.address_exclude(n2))
#print (n3)
for f in n3:
	h = str(f)
	print(h)
#	print(type(h))
	
#	print(type(f))
#	print(str(ipaddress.f))


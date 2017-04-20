import ipaddress
n1 = ipaddress.ip_network('192.0.2.0/28')
n2 = ipaddress.ip_network('192.0.2.1/32')
n3 = list(n1.address_exclude(n2))
print (n3)

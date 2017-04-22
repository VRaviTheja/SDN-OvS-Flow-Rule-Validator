#!/usr/bin/python
import ipaddress
def func_exclude_ip(mydict_ip,intersection_ip): 
	mydict_ip = ipaddress.ip_network(mydict_ip)
#	print("1111111")
	intersection_ip = ipaddress.ip_network(intersection_ip)
#	print("222222")
#	print(mydict_ip, type(mydict_ip), intersection_ip, type(intersection_ip))
	final = list(mydict_ip.address_exclude(intersection_ip))
#	print("3333333333333")
	last = []
#	print(final)
#	print(final)
	for f in final:
		h = str(f)
		print(h)
		last.append(h)
	if len(last) == 0:
		pot =  str(intersection_ip)
#		print([pot])
		return [pot]
	else:
#		print(last)
		return last 

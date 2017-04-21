#!/usr/bin/python
import ipaddress
def func_exclude_ip(mydict_ip,intersection_ip): 
	final = list(mydict_ip.address_exclude(intersection_ip))
	last = []
	for f in final:
		last.append(str(f))
	if len(last) == 0:
		return intersection_ip
	else:
		return last 

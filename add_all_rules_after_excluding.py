#!/usr/bin/bash
import copy
import Intersection_program
import pprint
Intersection_program.se_number = Intersection_program.se_number + 1
def add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list, mydict, gamma, pyt_src, pyt_dst):
	count = 0
	q = Intersection_program.se_number
	great = []
	for sip in src_ip_list:
		for dip in dst_ip_list:
			for sport in src_port_list:
				for dport in dst_port_list:
#					print(len(sport))
					cmydict = copy.deepcopy(gamma)
#					print(src_ip_list)
					cmydict['src_ip'] = sip
					cmydict['dst_ip'] = dip
					cmydict['src_start'] = str(sport[0])
					cmydict['src_end'] = str(sport[-1])
					cmydict['dst_start'] = str(dport[0])
					cmydict['dst_end'] = str(dport[-1])
					cmydict['aasno'] = str(Intersection_program.se_number)
					count = count + 1
#					print(cmydict)
					my_copy = copy.deepcopy(cmydict)
					great.append(my_copy)
#					Intersection_program.add_rule_to_patricia(pyt_src,pyt_dst,my_copy)
#					Intersection_program.add_rule_to_newft(my_copy)
					Intersection_program.se_number = Intersection_program.se_number + 1
	print("------",count,src_ip_list,dst_ip_list,len(src_port_list),len(src_port_list),"-------""\n")
#	pprint.pprint(Intersection_program.final_device_values)
#	gift = 564456546454
#	Getq = Intersection_program.JUST(gift)
#	print(Getq)
#	print(great)	
	return great

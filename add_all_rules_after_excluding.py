#!/usr/bin/bash

import testing2to3_python3_test_program

def add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_ip_list, mydict, gamma):
	for sip in src_ip_list:
		for dip in dst_ip_list:
			for sport in src_port_list:
				for dport in dst_port_list:
					cmydict = mydict
					cmydict['src_ip'] = sip
					cmydict['dst_ip'] = dip
					cmydict['src_start'] = sport[0]
					cmydict['src_end'] = sport[-1]
					cmydict['dst_start'] = dport[0]
					cmydict['dst_end'] = dport[-1]
					add_rule_to_patricia(pyt_src,pyt_dst,cmydict)
					add_rule_to_newft(cmydict)
	print("\n")

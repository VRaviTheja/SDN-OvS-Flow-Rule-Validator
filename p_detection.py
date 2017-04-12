#!/usr/bin/python

import pytricia 
import reading_file_to_dict
import sys
import pprint
import csv
import p_trie

def patricia(device_values):
        pyt_src = pytricia.PyTricia()
        pyt_dst = pytricia.PyTricia()
	return pyt_src,pyt_dst

def check_tcp_udp(flow_rule):
	if(flow_rule["nw_proto"]=="6"):
		return True
	else :
		return False	

def add_rule_to_patricia(pyt_src,pyt_dst,flow_rule):
	src_ip=flow_rule["src_ip"]
	dst_ip=flow_rule["dst_ip"]
	aas=flow_rule["aasno"]
	pyt_src.insert(src_ip,aas)
	pyt_dst.insert(dst_ip,aas)
	
def add_rule_to_newft(flow_rule):
	print >>f_new, flow_rule	

def finding_patricia_empty(pyt):
	if(len(pyt)==0):
		return True
	else :
		return False

		

def detection_algorithm(r,gamma):
	if(check_tcp_udp(r)==check_tcp_udp(gamma)):
		add_rule_to_newft(r)
		return
	if(r["src_ip"]==gamma["src_ip"] && r["dst_ip"]==gamma["dst_ip"]): #do subset here
		if(r["action "]==gamma["action "]):
			conflict_resolver(r,gamma,redundancy)
			print "Conflict is Redundancy : Sent to resolving"
		else:
			if(r["priority"]==gamma["priority"]):
				conflict_resolver(r,gamma,correlation)
				print "Conflict is Correlation : Sent to resolving"
			else:
				print "Conflict is Generalization : Sent to resolving"
	if(gamma["src_ip"]==r["src_ip"] && gamma["dst_ip"]==r["dst_ip"]): #do subset here
		if(r["action "]==gamma["action "]):
			conflict_resolver(r,gamma,redundancy)
		elif(r["priority"]==gamma["priority"]):
			conflict_resolver(r,gamma,correlation)
			print "Conflict is Correlation : Sent to resolving"
		else:
			conflict_resolver(r,gamma,shadowing)
			print "Conflict is Shadowing : Sent to resolving"
	
		

def creating_dict():
# Calls the csv_dict_list function, passing the named csv
        device_values = reading_file_to_dict.csv_dict_list(sys.argv[1])
# Prints the results nice and pretty like
        #pprint.pprint(device_values)
        return device_values


if __name__ == "__main__" :
        device_values = creating_dict()
	pyt_src,pyt_dst = patricia(device_values)
	finding_patricia_empty(pyt_src)
	r=device_values[0]
	gamma=device_values[1]
	f_new=open("new_flow_table","w+")
	print r["action "]
	#add_rule_to_newft(r)
	#add_rule_to_newft(gamma)
	detection_algorithm(gamma,r)
	#print r["nw_proto"]
	#add_rule_to_patricia(pyt_src,pyt_dst,r)
	#check_tcp_udp(r)
	#finding_patricia_empty(pyt_src)

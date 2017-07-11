#!/usr/bin/python

import pytricia
import python3_reading_file_to_dict 
import sys
import pprint
import csv
import p_trie
import excluding_ip
import excluding_port
import add_all_rules_after_excluding
import ipaddress
import copy
import os
from operator import itemgetter

final_device_values = []

def WriteDictToCSV(csv_file,csv_columns,dict_data):
    try:
        with open(csv_file, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in dict_data:
                writer.writerow(data)
    except IOError as err:
            print("I/O error{0}: ".format(err))    
    return

def creating_dict():
	device_values = python3_reading_file_to_dict.csv_dict_list(sys.argv[1])  # Calls the csv_dict_list function, passing the named csv
	device_values = sorted(device_values, key=itemgetter('priority')) 	 # device_values = sorted(device_values, key=itemgetter('priority'))
	return device_values


def check_layer2_layer4(a):
	if (a['src_ip'],a['dst_ip']) == ('0.0.0.0/0','0.0.0.0/0'):
		if (a['src_mac'],a['dst_mac'],a['src_start'],a['dst_end']) != ('00:00:00:00:00:00','00:00:00:00:00:00','0','0'):
			return True
		else:
			return False
	else :
		return False

def find_all_parents(pyt,ip):		# Finding list of all parents
	parent_all = []
	ip = pyt.parent(ip)
	while ip != None :
		parent_all.append(ip)
		ip = pyt.parent(ip)
	return parent_all

def check_tcp_udp(flow_rule):		# checking whether tcp or udp
	if(flow_rule["nw_proto"]=="6"):
		return "True"
	else :
		return "False"


def add_rule_to_patricia(pyt_src,pyt_dst,flow_rule):	#Adding rules to patricia and final_device values
	temp = []

	if pyt_src.has_key(flow_rule['src_ip']):
		temp = pyt_src.get(flow_rule['src_ip'])
		if int(flow_rule['aasno']) not in temp:
			temp.append(int(flow_rule['aasno']))
			pyt_src.insert(flow_rule['src_ip'],temp)
	else :
		pyt_src.insert(flow_rule['src_ip'],[int(flow_rule['aasno'])])
	temp1 = []
	if pyt_dst.has_key(flow_rule['dst_ip']):
		temp1 = pyt_dst.get(flow_rule['dst_ip'])
		if int(flow_rule['aasno']) not in temp1:
			temp1.append(int(flow_rule['aasno']))
			pyt_dst.insert(flow_rule['dst_ip'],temp1)
	else:
		pyt_dst.insert(flow_rule['dst_ip'],[int(flow_rule['aasno'])])
	return None


def subset_for_port(src_a_start, src_a_end, dst_a_start, dst_a_end, src_b_start, src_b_end, dst_b_start, dst_b_end):
	src_a = list(range(int(src_a_start), int(src_a_end)))
	dst_a = list(range(int(dst_a_start), int(dst_a_end)))
	src_b = list(range(int(src_b_start),int(src_b_end)))
	dst_b = list(range(int(dst_b_start), int(dst_b_end)))
	src_inter = list(set(src_a) & set(src_b))
	dst_inter = list(set(dst_a) & set(dst_b))
	if ((int(src_a_start) == int(src_b_start)) and (int(src_a_end) == int(src_b_end))) and ((int(dst_a_start) == int(dst_b_start)) and (int(dst_a_end) == int(dst_b_end))):
		var2 = "exact"
	elif ((int(src_a_start) >= int(src_b_start) and int(src_a_end) <= int(src_b_end)) and (int(dst_a_start) >= int(dst_b_start) and int(dst_a_end) <= int(dst_b_end))):
		var2 = "equal"
	elif ((int(src_a_start) <= int(src_b_start) and int(src_a_end) >= int(src_b_end)) and (int(dst_a_start) <= int(dst_b_start) and int(dst_a_end) >= int(dst_b_end))):
		var2 = "reverse"
	elif src_inter and dst_inter:
		var2 = "intersect"
	else :
		var2 = "completely"
	src_port_intersection_part = src_inter
	dst_port_intersection_part = dst_inter
	print("Length of Source port Intersection: ",len(src_port_intersection_part),"|| Length of Source port Intersection: ",len(dst_port_intersection_part))
	return var2,src_port_intersection_part,dst_port_intersection_part

def subset_for_ip(pyt_src, pyt_dst, gamma, mydict ,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules):
	compare = int(gamma['aasno'])
	if (compare in src_same_conflict_rules) and (compare in dst_same_conflict_rules):
		var1 = "exact"
		src_intersection_part = mydict['src_ip']
		dst_intersection_part = mydict['dst_ip']
	elif (((compare in src_paren_conflict_rules) or (compare in src_same_conflict_rules)) and ((compare in dst_paren_conflict_rules) or (compare in dst_same_conflict_rules))):
		var1 = "equal"
		src_intersection_part = mydict['src_ip']
		dst_intersection_part = mydict['dst_ip']
	elif (((compare in src_child_conflict_rules) or (compare in src_same_conflict_rules)) and ((compare in dst_child_conflict_rules) or (compare in dst_same_conflict_rules))):
		var1 = "reverse"
		src_intersection_part = gamma['src_ip']
		dst_intersection_part = gamma['dst_ip']
	elif ((compare in src_child_conflict_rules) and (compare in dst_paren_conflict_rules)):
		var1 = "intersect"
		src_intersection_part = gamma['src_ip']
		dst_intersection_part = mydict['dst_ip']
	elif ((compare in src_paren_conflict_rules) and (compare in dst_child_conflict_rules)):
		var1 = "intersect"
		src_intersection_part = mydict['src_ip']
		dst_intersection_part = gamma['dst_ip']


	var2,src_port_intersection_part,dst_port_intersection_part = subset_for_port(mydict['src_start'], mydict['src_end'], mydict['dst_start'], mydict['dst_end'], gamma['src_start'], gamma['src_end'], gamma['dst_start'], gamma['dst_end'])	# Now calling subset_for port

	print("Conflict_type in IPs: ", var1, "||  Conflict_type in PORTs: ", var2)

	if var1 == "exact" and var2 == "exact":
		final = "exact"
	elif var1 == "equal" and var2 == "equal":
		final = var1
	elif var1 == "reverse" and var2 == "reverse":
		final = var1
	elif var1 == "reverse" and var2 == "exact":
		final = "reverse"
	elif var1 == "exact" and var2 == "reverse":
		final = "reverse"
	elif var1 == "reverse" and var2 == "equal":
		final = "intersect"
	elif var1 == "equal" and var2 == "reverse":
		final = "intersect"
	elif var1 == "equal" and var2 == "exact":
		final = "equal"
	elif var1 == "exact" and var2 == "equal":
		final = "equal"
	elif var1 == "intersect" or var2 == "intersect":
		final = "intersect"
	elif var2 == "completely":
		final = "different"
	else :
		final = "intersect"
	return final,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part

def check_rule_for_similars(pyt_src,pyt_dst,mydict):
	src_conflict_rules = []
	dst_conflict_rules = []
	src_same_conflict_rules = []
	dst_same_conflict_rules = []
	if pyt_src.has_key(mydict['src_ip']):
		src_same_conflict_rules = src_same_conflict_rules + pyt_src.get(mydict['src_ip'])
	if pyt_dst.has_key(mydict['dst_ip']):
		dst_same_conflict_rules = dst_same_conflict_rules + pyt_dst.get(mydict['dst_ip'])
	src_child = pyt_src.children(mydict["src_ip"])
	src_paren = find_all_parents(pyt_src, mydict['src_ip'])
	dst_child = pyt_dst.children(mydict['dst_ip'])
	dst_paren = find_all_parents(pyt_dst, mydict['dst_ip'])
	src_child_conflict_rules = []
	dst_child_conflict_rules = []
	src_paren_conflict_rules = []
	dst_paren_conflict_rules = []
	if src_child != None :
		for i in src_child:
			src_child_conflict_rules = src_child_conflict_rules + pyt_src.get(i)
	if dst_child != None :
		for i in dst_child:
			dst_child_conflict_rules = dst_child_conflict_rules + pyt_dst.get(i)
	if src_paren != None :
		for i in src_paren:
			src_paren_conflict_rules = src_paren_conflict_rules + pyt_src.get(i)
	if dst_paren != None :
		for i in dst_paren:
			dst_paren_conflict_rules = dst_paren_conflict_rules + pyt_dst.get(i)

	src_all = src_child + src_paren
	dst_all = dst_child + dst_paren
	if src_all != None :
		for i in src_all:
			src_conflict_rules = src_conflict_rules + pyt_src.get(i)
	if dst_all != None :
		for i in dst_all:
			dst_conflict_rules = dst_conflict_rules + pyt_dst.get(i)
	src_conflict_rules = src_conflict_rules + src_same_conflict_rules
	dst_conflict_rules = dst_conflict_rules + dst_same_conflict_rules
	final_conflict_rules = list(set(src_conflict_rules) & set(dst_conflict_rules))

	return final_conflict_rules,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules


def detection_algorithm(gamma,mydict,pyt_src,pyt_dst,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules,rap):

	final,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part = subset_for_ip(pyt_src, pyt_dst, gamma, mydict,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules)

	print("Final_conflict_type: ",final)	

	if((check_tcp_udp(mydict) != check_tcp_udp(gamma)) or (final == "different")):
		print(mydict['aasno'],"has No conflict with ",gamma['aasno'])
	elif(final == "exact"):
		if(mydict["action "]==gamma["action "]):
			print(mydict['aasno'],"has Redundancy conflict with",gamma['aasno'])
		else:
			if(mydict["priority"]==gamma["priority"]):
				print(mydict['aasno'],"has Intersection_different_action_prompt conflict with",gamma['aasno'])
			else:
				print(mydict['aasno'],"has Sheilding conflict with",gamma['aasno'])
	elif(final == "equal"): #do subset here
		if(mydict["action "]==gamma["action "]):
			print(mydict['aasno'],"has Redundancy conflict with",gamma['aasno'])
		else:
			if(mydict["priority"]==gamma["priority"]):
				print(mydict['aasno'],"has Intersection_different_action_prompt conflict with",gamma['aasno'])
			else:
				print(mydict['aasno'],"has Abstraction conflict with",gamma['aasno'])
	elif(final == "reverse"): # find Reverse subset here
		if(mydict["action "]==gamma["action "]):
			print(mydict['aasno'],"has Redundancy_removing conflict with",gamma['aasno'])
		else:
			if(mydict["priority"]==gamma["priority"]):
				print(mydict['aasno'],"has Intersection_different_action_prompt conflict with",gamma['aasno'])
			else:
				print(mydict['aasno'],"has Sheilding conflict with",gamma['aasno'])
	elif(final == "intersect"):
		if(mydict["action "]==gamma["action "]):
			print(mydict['aasno'],"has Intersection_SAME_action_prompt conflict with",gamma['aasno'])
		else:
			if(mydict["priority"]==gamma["priority"]):
				print(mydict['aasno'],"has Intersection_different_action_prompt with same priority conflict with",gamma['aasno'])
			else:
				print(mydict['aasno'],"has Intersection_different_action_prompt conflict with",gamma['aasno'])
	print("---------------------------")
	return rap

def detection(device_values,pyt_src,pyt_dst):					# Main Detection
	print("Hello detection starts from here")
	i = 0
	rap = 100
	for mydict in device_values:
		i = int(mydict['aasno'])-1
		for gamma in device_values:
			if mydict == gamma:
				continue
			if int(gamma['aasno']) in conflict_rule_numbers[i]:
				rap1 = detection_algorithm(gamma, mydict, pyt_src, pyt_dst,src_same_conflict_rules[i],src_child_conflict_rules[i],src_paren_conflict_rules[i],dst_same_conflict_rules[i],dst_child_conflict_rules[i],dst_paren_conflict_rules[i],rap)
			else:
				print(mydict['aasno'],"has No conflict with ",gamma['aasno'])
	print("DETECTION COMPLETE:")


if __name__ == "__main__" :
	device_values = creating_dict()
	pyt_src,pyt_dst = p_trie.patricia()
	for x in device_values:
		add_rule_to_patricia(pyt_src,pyt_dst,x)
	i = 0
	conflict_rule_numbers = []
	src_same_conflict_rules = []
	src_child_conflict_rules = []
	src_paren_conflict_rules = []
	dst_same_conflict_rules = []
	dst_child_conflict_rules = []
	dst_paren_conflict_rules = []
	for x in device_values:
		a,b,c,d,e,f,g = check_rule_for_similars(pyt_src,pyt_dst,x)
		conflict_rule_numbers.append(a)
		src_same_conflict_rules.append(b)
		src_child_conflict_rules.append(c)
		src_paren_conflict_rules.append(d)
		dst_same_conflict_rules.append(e)
		dst_child_conflict_rules.append(f)
		dst_paren_conflict_rules.append(g)
		i = i + 1
	detection(device_values,pyt_src,pyt_dst)

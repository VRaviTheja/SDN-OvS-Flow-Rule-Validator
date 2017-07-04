#!/usr/bin/python

import time
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
se_number = 1001 


"""def WriteDictToCSV(csv_file,csv_columns,dict_data):
    try:
        with open(csv_file, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in dict_data:
                writer.writerow(data)
    except IOError as err:
            print("I/O error{0}: ".format(err))    
    return
"""

def creating_dict():
	device_values = python3_reading_file_to_dict.csv_dict_list(sys.argv[1])  # Calls the csv_dict_list function, passing the named csv
	i = 0
	for x in device_values:
		x['priority'] = int(x['priority'])
		device_values[i] = x
		i = i+1
	device_values = sorted(device_values, key=itemgetter('priority')) 	 # device_values = sorted(device_values, key=itemgetter('priority'))
#	pprint.pprint(device_values)
	i = 0     					 # Prints the results nice and pretty like
	for x in device_values:
		x['priority'] = str(x['priority'])
		device_values[i] = x
		i = i+1
	temp = []
	"""for x in device_values:
		temp.append(int(x['priority']))
	print(temp)"""
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


"""def add_rule_to_newft(flow_rule):	#Adding rule to flow
	with open("new_table99", "a") as myfile:
		myfile.write(str(flow_rule))
"""

def finding_patricia_empty(pyt):	#Checking whether patricia tree is empty or not
	if(len(pyt)==0):
		return True
	else :
		return False

def check_and_delete_in_final_device_values(flow_rule):
	for x in final_device_values:
		if x['aasno'] == flow_rule['aasno']:
			final_device_values.remove(flow_rule)
			break
		else:
			continue	


def add_rule_to_patricia(pyt_src,pyt_dst,flow_rule):	#Adding rules to patricia and final_device values
	temp = []
	isthere = 0
	if len(final_device_values) == 0:
		final_device_values.append(flow_rule)
	else:
		for x in final_device_values:
			if x['aasno'] == flow_rule['aasno']:
				isthere = 1
				break
		if isthere != 1:
			final_device_values.append(flow_rule)
			isthere = 0

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
	src_a = list(range(int(src_a_start), int(src_a_end)+1))
	dst_a = list(range(int(dst_a_start), int(dst_a_end)+1))
	src_b = list(range(int(src_b_start), int(src_b_end)+1))
	dst_b = list(range(int(dst_b_start), int(dst_b_end)+1))
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
	"""
	temp = []
	src_port_intersection = []
	dst_port_intersection = []
	for x in src_inter:
		if temp :
			temp.append(x)
			continue
		if x-1 == temp[-1]:
			temp.append(x)
			continue
		else:
			src_port_intersection = [temp]
			temp = []
	"""
	src_inter.sort()
	dst_inter.sort()
	src_port_intersection_part = src_inter
	dst_port_intersection_part = dst_inter
#	print("Length of Source port Intersection: ",len(src_port_intersection_part),"|| Length of Source port Intersection: ",len(dst_port_intersection_part))
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

#	print("Conflict_type in IPs: ", var1, "||  Conflict_type in PORTs: ", var2)

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
	add_rule_to_patricia(pyt_src, pyt_dst, mydict)	#Adding trule to patricia
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
	delete_rule_from_pt_ft(pyt_src, pyt_dst, mydict)

	return final_conflict_rules,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules


def detection_algorithm(gamma,mydict,pyt_src,pyt_dst,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules,rap):

	final,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part = subset_for_ip(pyt_src, pyt_dst, gamma, mydict,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules)

#	print("Final_conflict_type: ",final)	

	if((check_tcp_udp(mydict) != check_tcp_udp(gamma)) or (final == "different")):
		add_rule_to_patricia(pyt_src,pyt_dst,mydict)
#		add_rule_to_newft(mydict)
#		print("Just added")
	elif(final == "exact"):
		if(mydict["action "]==gamma["action "]):
#			print("Conflict is Redundancy : Sent to resolving")
			rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"redundancy",rap)
		else:
			if(mydict["priority"]==gamma["priority"]):
#				print("Conflict is Intersection_different_action_prompt : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
			else:
#				print("Conflict is Shielding : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"shadowing",rap)
	elif(final == "equal"): #do subset here
		if(mydict["action "]==gamma["action "]):
#			print("Conflict is Redundancy : Sent to resolving")
			rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"redundancy",rap)
		else:
			if(mydict["priority"]==gamma["priority"]):
#				print("Conflict is Intersection_different_action_prompt : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
			else:
#				print("Conflict is Abstraction : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"generalization",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
	elif(final == "reverse"): # find Reverse subset here
		if(mydict["action "]==gamma["action "]):
#			print("Conflict is Redundancy_gamma_Removing : Sent to resolving")
			rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"redundancy_gamma_removing",rap)
		else:
			if(mydict["priority"]==gamma["priority"]):
#				print("Conflict is Intersection_different_action_prompt : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
			else:
#				print("Conflict is Shielding : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"shadowing",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
	elif(final == "intersect"):
		if(mydict["action "]==gamma["action "]):
#			print("Conflict is Intersection_same_action : Sent to resolving")
			rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"overlap",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
		else:
			if(mydict["priority"]==gamma["priority"]):
#				print("Conflict is Intersection_different_action_prompt : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"correlation_prompt",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
			else:
#				print("Conflict is Intersection_different_action : Sent to resolving")
				rap = conflict_resolver(pyt_src, pyt_dst, mydict,gamma,"correlation",rap,src_intersection_part,dst_intersection_part,src_port_intersection_part,dst_port_intersection_part)
#	print("---------------------------")
	return rap


def delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma):
	check_and_delete_in_final_device_values(gamma)	# Calling to check and delete final_device_values
	temp = []
	Ips = gamma['src_ip']
	prio = int(gamma['aasno'])
	temp = pyt_src.get(Ips)
	if temp is not None:
		if (prio not in temp):
			return None
		else:
			if len(temp) > 1 :
				temp.remove(prio)
				pyt_src.insert(Ips,temp)
			else:
				pyt_src.delete(Ips)
	temp = []					# For Destination insertion
	Ipd = gamma['dst_ip']
	temp = pyt_dst.get(Ipd)
	if temp is not None:
		if (prio not in temp):
			return None
		else:
			if len(temp) > 1 :
				temp.remove(prio)
				pyt_dst.insert(Ipd,temp)
			else:
				pyt_dst.delete(Ipd)
	"""bad_words = ["'aasno': '"+str(prio)+"',"]	# deleting a flow fro flow table
	with open('new_table99') as oldfile, open('new_table22', 'w') as newfile:
		for line in oldfile:
			if not any(bad_word in line for bad_word in bad_words):
				newfile.write(line)
	with open('new_table99', 'w+') as output, open('new_table22', 'r') as input1:
		while True:
			data = input1.read(100000)
			if data == '': 			# end of file reached
				break
			output.write(data)
	"""


def conflict_resolver(pyt_src, pyt_dst, mydict, gamma, conflict_type,rap,src_intersection_part = None,dst_intersection_part = None,src_port_intersection_part = None,dst_port_intersection_part = None):
	if(conflict_type=="shadowing"):
		delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
		rap = 200
#		print("Removed gamma R Holded")

	elif(conflict_type=="redundancy_gamma_removing"):
		delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
		add_rule_to_patricia(pyt_src, pyt_dst, mydict)
#		add_rule_to_newft(mydict)
#		print("Gamma Removed R adds")

	elif(conflict_type == "redundancy"):
#		print("No adding of R")
		pass

	elif(conflict_type=="generalization"):
		rap = 200
		src_ip_list=excluding_ip.func_exclude_ip(gamma["src_ip"],src_intersection_part)
		dst_ip_list=excluding_ip.func_exclude_ip(gamma["dst_ip"],dst_intersection_part)
		src_port_list=excluding_port.func_exclude_port(list(range(int(gamma["src_start"]),int(gamma["src_end"])+1)),src_port_intersection_part)
		dst_port_list=excluding_port.func_exclude_port(list(range(int(gamma["dst_start"]),int(gamma["dst_end"])+1)),dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list, mydict, gamma, pyt_src, pyt_dst)
		for x in f_list:
			add_rule_to_patricia(pyt_src, pyt_dst, x)
#			add_rule_to_newft(x)
		delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
#		print("gamma Splitted")

	elif(conflict_type=="overlap"):
		rap = 200
		src_ip_list=excluding_ip.func_exclude_ip(gamma["src_ip"],src_intersection_part)
		dst_ip_list=excluding_ip.func_exclude_ip(gamma["dst_ip"],dst_intersection_part)
		src_port_list=excluding_port.func_exclude_port(list(range(int(gamma["src_start"]),int(gamma["src_end"])+1)),src_port_intersection_part)
		dst_port_list=excluding_port.func_exclude_port(list(range(int(gamma["dst_start"]),int(gamma["dst_end"])+1)),dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list, mydict, gamma, pyt_src, pyt_dst)
		for x in f_list:
			add_rule_to_patricia(pyt_src, pyt_dst, x)
#			add_rule_to_newft(x)
		delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
#		print("gamma Splitted")

	elif(conflict_type=="correlation_prompt"):
		rap = 200
		src_ip_list=excluding_ip.func_exclude_ip(gamma["src_ip"],src_intersection_part)
		dst_ip_list=excluding_ip.func_exclude_ip(gamma["dst_ip"],dst_intersection_part)
		src_port_list=excluding_port.func_exclude_port(list(range(int(gamma["src_start"]),int(gamma["src_end"])+1)),src_port_intersection_part)
		dst_port_list=excluding_port.func_exclude_port(list(range(int(gamma["dst_start"]),int(gamma["dst_end"])+1)),dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list, mydict, gamma, pyt_src, pyt_dst)
		for x in f_list:
			add_rule_to_patricia(pyt_src, pyt_dst, x)
#			add_rule_to_newft(x)
		delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
#		print("gamma Splitted:")	

	elif(conflict_type=="correlation"):
		rap = 200
		src_ip_list=excluding_ip.func_exclude_ip(gamma["src_ip"],src_intersection_part)
		dst_ip_list=excluding_ip.func_exclude_ip(gamma["dst_ip"],dst_intersection_part)
		src_port_list=excluding_port.func_exclude_port(list(range(int(gamma["src_start"]),int(gamma["src_end"])+1)),src_port_intersection_part)
		dst_port_list=excluding_port.func_exclude_port(list(range(int(gamma["dst_start"]),int(gamma["dst_end"])+1)),dst_port_intersection_part)
		f_list = add_all_rules_after_excluding.add_all_rules(src_ip_list, dst_ip_list, src_port_list, dst_port_list, mydict, gamma, pyt_src, pyt_dst)	
		for x in f_list:
			add_rule_to_patricia(pyt_src, pyt_dst, x)
#			add_rule_to_newft(x)
		delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
#		print("gamma Splitted")

	return rap


def detection(device_values,pyt_src,pyt_dst):					# Main Detection
	print("Hello detection starts from here")
	for mydict in device_values :
		print(mydict['priority'])
		if check_layer2_layer4(mydict) == True :
#			print(("\nReconcile %s" %mydict['aasno']))
			pass
		else :
#			print(("\nNO Reconc %s" %mydict['aasno']))
			conflict_rule_numbers,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules = check_rule_for_similars(pyt_src,pyt_dst,mydict)     #Gives list of conflict ru
#			print("Conflicted_numbers: ",conflict_rule_numbers)
			if len(conflict_rule_numbers) == 0 :
				add_rule_to_patricia(pyt_src,pyt_dst,mydict)
#				add_rule_to_newft(mydict)
			else :
				fd = final_device_values
				rap = 100
				for i in conflict_rule_numbers:
					it = str(i)
#					print("\n",it)
					my_item = 100 
					for item in fd:
						if item['aasno'] == it:
							my_item = item
							break
					if my_item != 100:
						gamma = my_item
						rap1 = detection_algorithm(gamma, mydict, pyt_src, pyt_dst,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules,rap)
					else:
						pass
				if rap1 == 200:
					add_rule_to_patricia(pyt_src,pyt_dst,mydict)
#					add_rule_to_newft(mydict)
	print("DETECTION COMPLETE:")

start_time = time.time()


if __name__ == "__main__" :
	device_values = creating_dict()
	pyt_src,pyt_dst = p_trie.patricia()
	detection(device_values,pyt_src,pyt_dst)
#	pprint.pprint(final_device_values)
	print(len(final_device_values))
#	csv_columns = final_device_values[0].keys()
#	currentPath = os.getcwd()
#	csv_file = currentPath + "/csv/Outputflows.csv"
#	WriteDictToCSV(csv_file,csv_columns,final_device_values)
	print("--- %s seconds ---" % (time.time() - start_time))

#!/usr/bin/python

import pytricia
import reading_file_to_dict
import sys
import pprint
import csv
import p_trie

f_new=open("new_table99","w+")

def creating_dict():	
	device_values = reading_file_to_dict.csv_dict_list(sys.argv[1])   # Calls the csv_dict_list function, passing the named csv
	pprint.pprint(device_values)     # Prints the results nice and pretty like
	return device_values

# Finding list of all parents
def find_all_parents(pyt,ip):
        parent_all = []
        ip = pyt.parent(ip)
        while ip != None :
                parent_all.append(ip)
                ip = pyt.parent(ip)
        return parent_all

def check_tcp_udp(flow_rule):			# checking whether tcp or udp
        if(flow_rule["nw_proto"]=="6"):
                return True
        else :
                return False


def add_rule_to_newft(flow_rule):		#Adding rule to flow
        print >>f_new, flow_rule

def finding_patricia_empty(pyt):		#Checking whether patricia tree is empty or not
        if(len(pyt)==0):
                return True
        else :
                return False

def add_rule_to_patricia(pyt_src,pyt_dst,flow_rule):
	temp = []
        if pyt_src.has_key(flow_rule['src_ip']):
                temp = pyt_src.get(flow_rule['src_ip'])
                temp.append(int(flow_rule['aasno']))
                pyt_src.insert(flow_rule['src_ip'],temp)
        else :
                pyt_src.insert(flow_rule['src_ip'],[int(flow_rule['aasno'])])
        temp1 = []
	if pyt_dst.has_key(flow_rule['dst_ip']):
                temp1 = pyt_dst.get(flow_rule['dst_ip'])
                temp1.append(int(flow_rule['aasno']))
                pyt_dst.insert(flow_rule['dst_ip'],temp1)
        else:
                pyt_dst.insert(flow_rule['dst_ip'],[int(flow_rule['aasno'])])
	return None

def check_exact_proceed(Ips,Ipd,prio,pyt_src,pyt_dst):
        temp = []
        if pyt_src.has_key(Ips):
                temp = pyt_src.get(Ips)
                temp.append(prio)
                pyt_src.insert(Ips,temp)
        else:
                pyt_src.insert(Ips,[prio])
# For Destination insertion
        temp = []
        if pyt_dst.has_key(Ipd):
                temp = pyt_dst.get(Ipd)
                temp.append(prio)
                pyt_dst.insert(Ipd,temp)
        else:
                pyt_dst.insert(Ipd,[prio])
        print "Inserted  ---"+str(prio)



def subset_for_port(src_a_start, src_a_end, dst_a_start, dst_a_end, src_b_start, src_b_end, dst_b_start, dst_b_end):
        src_a = range(int(src_a_start), int(src_a_end))
        dst_a = range(int(dst_a_start), int(dst_a_end))
        src_b = range(int(src_b_start),int(src_b_end))
        dst_b = range(int(dst_b_start), int(dst_b_end))
        print "subset for port"
        if ((int(src_a_start) <= int(src_b_start) and int(src_a_end) >= int(src_b_end)) and (int(dst_a_start) <= int(dst_b_start) and int(dst_a_end) >= int(dst_b_end))):
                var2 = "equal"
        elif ((int(src_a_start) >= int(src_b_start) and int(src_a_end) <= int(src_b_end)) and (int(dst_a_start) >= int(dst_b_start) and int(dst_a_end) <= int(dst_b_end))):
                var2 = "reverse"
        elif (set(src_a) & set(src_b)) and (set(dst_a) & set(dst_b)):
                var2 = "intersect"
	else :
		var2 = "intersect"
        return var2

def subset_for_ip(pyt_src, pyt_dst, mydict, r ,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules):
	'''print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
        print src_same_conflict_rules
	print src_child_conflict_rules
	print src_paren_conflict_rules
	print dst_same_conflict_rules
	print dst_child_conflict_rules
	print dst_paren_conflict_rules
	print mydict['aasno']	
	print (mydict['aasno'] in src_paren_conflict_rules)
	print (mydict['aasno'] in src_same_conflict_rules)
	print type(src_paren_conflict_rules)
	print type(mydict['aasno'])
	print "@@@@@@@@@@@@@@"
	'''
	compare = int(mydict['aasno'])
        if (((compare in src_paren_conflict_rules) or (compare in src_same_conflict_rules)) and ((compare in dst_paren_conflict_rules) or (compare in dst_same_conflict_rules))):
                var1 = "equal"
        elif (((compare in src_child_conflict_rules) or (compare in src_same_conflict_rules)) and ((compare in dst_child_conflict_rules) or (compare in dst_same_conflict_rules))):
                var1 = "reverse"
        elif ((compare in src_child_conflict_rules) and (compare in dst_paren_conflict_rules)) or ((compare in src_paren_conflict_rules) and  (compare in dst_child_conflict_rules)) :
                var1 = "intersect"
# Swapping r gamma
	temp = r
	r = mydict
	mydict = temp
# Now calling subset_for port
        var2 = subset_for_port(r['src_start'], r['src_end'], r['dst_start'], r['dst_end'], mydict['src_start'], mydict['src_end'], mydict['dst_start'], mydict['dst_end'])
# Comparing port and Ip
	#return var1, var2
	print var1, var2
	print "End --------------------of subset"
	if var1 == "equal" and var2 == "equal":
                return var1
        elif var1 == "reverse" and var2 == "reverse":
                return var1
        elif var1 == "reverse" and var2 == "equal":
                return "intersect"
        elif var1 == "equal" and var2 == "reverse":
                return "intersect"
        elif var1 == "intersect" or var2 == "intersect":
                return "intersect"
	else :
		return "intersect"


def check_rule_for_similars(pyt_src,pyt_dst,mydict):
        print "check_similar started"
	src_conflict_rules = []
	dst_conflict_rules = []
	src_same_conflict_rules = []
	dst_same_conflict_rules = []
	if pyt_src.has_key(mydict['src_ip']):
		src_conflict_rules = src_conflict_rules + pyt_src.get(mydict['src_ip'])
		src_same_conflict_rules = src_conflict_rules
	if pyt_dst.has_key(mydict['dst_ip']):
		dst_conflict_rules = dst_conflict_rules + pyt_dst.get(mydict['dst_ip'])
		dst_same_conflict_rules = dst_conflict_rules
		print "Inside destination"
		print src_conflict_rules, dst_conflict_rules	
	add_rule_to_patricia(pyt_src, pyt_dst, mydict)
	print len(pyt_src), len(pyt_dst)        
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
	print "---------------"
	print src_child, src_paren, dst_child, dst_paren
	print "---------"
        if src_all != None :
                for i in src_all:
                        src_conflict_rules = src_conflict_rules + pyt_src.get(i)
        if dst_all != None :
                for i in dst_all:
                        dst_conflict_rules = dst_conflict_rules + pyt_dst.get(i)
        final_conflict_rules = list(set(src_conflict_rules) & set(dst_conflict_rules))
	print src_conflict_rules, dst_conflict_rules
        print final_conflict_rules
        print "check_similar finished"
#	pyt_src.delete(mydict['src_ip'])
#	pyt_dst.delete(mydict['dst_ip'])
        return final_conflict_rules,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules


def check_layer2_layer4(a):
        if (a['src_ip'],a['dst_ip']) == ('0.0.0.0/0','0.0.0.0/0'):	
		if (a['src_mac'],a['dst_mac'],a['src_start'],a['dst_end']) != ('00:00:00:00:00:00','00:00:00:00:00:00','0','0'):
                	return True
		else:
			return False
        else :
                return False

'''
def detection_algorithm(r,gamma,pyt_src, pyt_dst):
	if(check_tcp_udp(r)==check_tcp_udp(gamma)):
		add_rule_to_newft(r)
		return
	if(subset(pyt_src,pyt_dst,r,gamma)=="equal"): #do subset here
		if(r["action "]==gamma["action "]):
                        print "Conflict is Redundancy : Sent to resolving"
			conflict_resolver(gamma,r,"redundancy")
		else:
			if(r["priority"]==gamma["priority"]):
                                print "Conflict is Correlation : Sent to resolving"
				conflict_resolver(r,gamma,"correlation")
			else:
				print "Conflict is Generalization : Sent to resolving"
				conflict_resolver(r,gamma,"correlation")
	if(subset(pyt_src,pyt_dst,r,gamma)=="reverse"): #do subset here
		if(r["action "]==gamma["action "]):
			print "Conflict is Redundancy : Sent to resolving"
			conflict_resolver(r,gamma,"redundancy")
		elif(r["priority"]==gamma["priority"]):
			print "Conflict is Correlation : Sent to resolving"
			conflict_resolver(r,gamma,"correlation")
		else:
                        print "Conflict is Shadowing : Sent to resolving"
			conflict_resolver(r,gamma,"shadowing")
	if(subset(pyt_src,pyt_dst,r,gamma)=="intersection"):
		if(r["action "]==gamma["action "]):
			print "Conflict is Overlap : Sent to resolving"
                        conflict_resolver(r,gamma,"overlap")
		else :
                        print "Conflict is Correlation : Sent to resolving"
			conflict_resolver(r,gamma,"correlation")
'''

def detection_algorithm(r,t,pyt_src,pyt_dst,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules):
        print r,t,"\t"
        rock = subset_for_ip(pyt_src, pyt_dst, r, t,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules)
	print rock

def Reconcile(device_values, mydict):
	print "Inside Reconcile"
	return True


def detection(device_values,pyt_src,pyt_dst):
        print("Hello detection starts from here")
        for mydict in device_values :
		if check_layer2_layer4(mydict) == True :
                        print("Reconcile %s" %mydict['aasno'])
			Reconcile(device_values, mydict)
                else :
                        print("NO Reconc %s" %mydict['aasno'])
			#add_rule_to_patricia(pyt_src, pyt_dst, mydict)
                	conflict_rule_numbers,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules = check_rule_for_similars(pyt_src,pyt_dst,mydict)     #Gives list of conflict ru
			print conflict_rule_numbers,"Conflicted_numbers"
                	if len(conflict_rule_numbers) == 0 :
                        	add_rule_to_newft(mydict)
                	else :
                        	for i in conflict_rule_numbers :
                                	it = str(i)
                                	gamma = (item for item in device_values if item['aasno'] == it).next()
                                	detection_algorithm(gamma, mydict, pyt_src, pyt_dst,src_same_conflict_rules,src_child_conflict_rules,src_paren_conflict_rules,dst_same_conflict_rules,dst_child_conflict_rules,dst_paren_conflict_rules)
        #check_rule_for_similars(pyt_src,pyt_dst,device_values[0])
        print "DETECTION COMPLETE:"


if __name__ == "__main__" :
	device_values = creating_dict()
	pyt_src,pyt_dst = p_trie.patricia()
	detection(device_values,pyt_src,pyt_dst)	
		

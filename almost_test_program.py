#!/usr/bin/python

import pytricia
import reading_file_to_dict
import sys
import pprint
import csv
import p_trie

#device_values = []

f=open("new_flow_table","w+")

def creating_dict():
# Calls the csv_dict_list function, passing the named csv
        device_values = reading_file_to_dict.csv_dict_list(sys.argv[1])
# Prints the results nice and pretty like
        pprint.pprint(device_values)
        return device_values

def find_all_parents(pyt,ip):
        parent_all = []
#       print ip
        ip = pyt.parent(ip)
        while ip != None :
                parent_all.append(ip)
                ip = pyt.parent(ip)
        return parent_all

def subset_for_port(src_a_start, src_a_end, dst_a_start, dst_a_end, src_b_start, src_b_end, dst_b_start, dst_b_end):
	if (src_a_start <= src_b_start  && src_a_end <= src_b_end) && (dst_a_start <= dst_b_start  && dst_a_end <= dst_b_end) :
		return "equal"
	elif (src_a_start >= src_b_start  && src_a_end >= src_b_end) && (dst_a_start >= dst_b_start  && dst_a_end >= dst_b_end) :
                return "reverse"
	elif (


def subset(pyt_src, pyt_dst, r, mydict):
	src_child = pyt_src.children(mydict['src_ip'])
        src_paren = find_all_parents(pyt_src, mydict['src_ip'])
        dst_child = pyt_dst.children(mydict['dst_ip'])
        dst_paren = find_all_parents(pyt_dst, mydict['dst_ip'])
	src_child_conflict_rules = []
        if src_child != None :
                for i in src_child:
                        src_child_conflict_rules = src_child_conflict_rules + pyt_src.get(i)
        dst_child_conflict_rules = []
        if dst_child != None :
                for i in dst_child:
                        dst_child_conflict_rules = dst_child_conflict_rules + pyt_dst.get(i)
	src_paren_conflict_rules = []
        if src_paren != None :
                for i in src_paren:
                        src_paren_conflict_rules = src_paren_conflict_rules + pyt_src.get(i)
        dst_paren_conflict_rules = []
        if dst_paren != None :
                for i in dst_paren:
                        dst_paren_conflict_rules = dst_paren_conflict_rules + pyt_dst.get(i)
	if (r['aasno'] in src_child_conflict_rules) && (r['aasno'] in dst_child_conflict_rules):
		return "equal"
	elif (r['aasno'] in src_paren_conflict_rules) && (r['aasno'] in dst_paren_conflict_rules):
		return "reverse"
	elif ((r['aasno'] in src_child_conflict_rules) && (r['aasno'] in dst_paren_conflict_rules)) || ((r['aasno'] in src_paren_conflict_rules) && (r['aasno'] in dst_child_conflict_rules)) :
		return "intersect"

	print "This is subset"

def check_rule_for_similars(pyt_src,pyt_dst,mydict):
	print "check_similar started"
        src_child = pyt_src.children(mydict['src_ip'])
        src_paren = find_all_parents(pyt_src, mydict['src_ip'])
        dst_child = pyt_dst.children(mydict['dst_ip'])
        dst_paren = find_all_parents(pyt_dst, mydict['dst_ip'])
        src_all = src_child + src_paren
        dst_all = dst_child + dst_paren
        src_conflict_rules = []
	if src_all != None :
        	for i in src_all:
                	src_conflict_rules = src_conflict_rules + pyt_src.get(i)
        dst_conflict_rules = []
	if dst_all != None :
        	for i in dst_all:
                	dst_conflict_rules = dst_conflict_rules + pyt_dst.get(i)
        final_conflict_rules = list(set(src_conflict_rules) & set(dst_conflict_rules))
        print final_conflict_rules
        print "check_similar finished"
        return final_conflict_rules


def detection_algorithm(r,t,pyt_src, pyt_dst):
        print r,t,"\t"
#	subset(pyt_src, pyt_dst, r, t)


def detection(device_values,pyt_src,pyt_dst):
        print("Hello detection starts from here")
        for mydict in device_values :
                conflict_rule_numbers = check_rule_for_similars(pyt_src, pyt_dst, mydict) #Gives list of conflict ru
		if len(conflict_rule_numbers) == 0 :
			pass
			#add_rule_to_patricia(pyt_src, pyt_dst, mydict)
			#add_rule_to_newft(mydict)
		else :
                	for i in conflict_rule_numbers :
				it = str(i)
				gamma = (item for item in device_values if item['aasno'] == it).next()
                        	detection_algorithm(gamma, mydict, pyt_src, pyt_dst)
        #check_rule_for_similars(pyt_src,pyt_dst,device_values[0])
        print "DETCETION COMPLETE:"


if __name__ == "__main__" :
        device_values = creating_dict()
        pyt_src,pyt_dst = p_trie.patricia(device_values)
        detection(device_values,pyt_src,pyt_dst)

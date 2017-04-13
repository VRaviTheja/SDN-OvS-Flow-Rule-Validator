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

def subset():
	print "This is subset"

def check_rule_for_similars(pyt_src,pyt_dst,mydict):
	print "check_similar started"
        src_child = pyt_src.children(mydict['src_ip'])
        src_paren = pyt_src.parent(mydict['src_ip'])
        dst_child = pyt_dst.children(mydict['dst_ip'])
        dst_paren = pyt_dst.parent(mydict['dst_ip'])
	src_paren = [src_paren]
        dst_paren = [dst_paren]
        src_all = src_child + src_paren
        dst_all = dst_child + dst_paren
        src_conflict_rules = []
	if src_all != None
        	for i in src_all:
                print i
                src_conflict_rules = src_conflict_rules + pyt_src.get(i)
        dst_conflict_rules = []
	if dst_all != None :
        	for i in dst_all:
                	dst_conflict_rules = dst_conflict_rules + pyt_dst.get(i)
        print src_conflict_rules
        print dst_conflict_rules
        print "\n"
        final_conflict_rules = list(set(src_conflict_rules) & set(dst_conflict_rules))
        print final_conflict_rules
        print "check_similar finished"
        return final_conflict_rules


def detection_algorithm(r,t):
        print r,t,"\t"


def detection(device_values,pyt_src,pyt_dst):
        print("Hello detection starts from here")
        for mydict in device_values :
                conflict_rule_numbers = check_rule_for_similars(pyt_src, pyt_dst, mydict) #Gives list of conflict ru
		if len(conflict_rule_numbers) == 0 :
			add_rule_to_patricia(pyt_src, pyt_dst, mydict)
			add_rule_to_newft(mydict)
		else :
                	for i in conflict_rule_numbers :
				it = str(i)
				gamma = (item for item in device_values if item['aasno'] == it).next()
                        	detection_algorithm(gamma, mydict)
        #check_rule_for_similars(pyt_src,pyt_dst,device_values[0])
        print "DETCETION COMPLETE:"


if __name__ == "__main__" :
        device_values = creating_dict()
        pyt_src,pyt_dst = p_trie.patricia(device_values)
        detection(device_values,pyt_src,pyt_dst)


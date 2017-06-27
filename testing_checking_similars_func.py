#!/usr/bin/python

import pytricia
import reading_file_to_dict
import sys
import pprint
import csv
import p_trie

#device_values = []
a = {}

def creating_dict():
# Calls the csv_dict_list function, passing the named csv
        device_values = reading_file_to_dict.csv_dict_list(sys.argv[1])
# Prints the results nice and pretty like
        pprint.pprint(device_values)
        return device_values
def check_rule_for_similars(pyt_src,pyt_dst,dict):

        src_child = pyt_src.children(dict['src_ip'])
        src_paren = pyt_src.parent(dict['src_ip'])
        dst_child = pyt_dst.children(dict['dst_ip'])
        dst_paren = pyt_dst.parent(dict['dst_ip'])
	'''print "src_child: befor {}".format(src_child)
	print "src_parent:before"+src_paren
	print "dst_child: before {}".format(dst_child)
        print "dst_parent:before"+dst_paren
	'''
        src_paren = [src_paren]
        dst_paren = [dst_paren]
        src_all = src_child + src_paren
        dst_all = dst_child + dst_paren
	'''print "src_child: after {}".format(src_child)
        print "src_parent:after {}".format(src_paren)
	print "src_all : {}".format(src_all)
	print "\n\n dst_child: after {}".format(dst_child)
        print "dst_parent:after {}".format(dst_paren)
        print "dst_all : {}".format(dst_all)
	'''
        src_conflict_rules = []
	for i in src_all:
		print i
                src_conflict_rules = src_conflict_rules + pyt_src.get(i)
        dst_conflict_rules = []
        for i in dst_all:
                dst_conflict_rules = dst_conflict_rules + pyt_dst.get(i)
        print src_conflict_rules
        print dst_conflict_rules   
	print "\n"
	final_conflict_rules = list(set(src_conflict_rules) & set(dst_conflict_rules))
	print final_conflict_rules
        print "check_similar finished"
	return final_conflict_rules
def detection(device_values,pyt_src,pyt_dst):

        print("Hello detection starts from here")
        check_rule_for_similars(pyt_src,pyt_dst,device_values[0])
        print "DETCETION COMPLETE:"

if __name__ == "__main__" :
        device_values = creating_dict()
        pyt_src,pyt_dst = p_trie.patricia(device_values)
        detection(device_values,pyt_src,pyt_dst)


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


def check_layer2_layer4(d,num):
	a = d[num]
	if (a['src_mac'],a['dst_mac'],a['src_port'],a['dst_port']) != ('00:00:00:00:00:00','00:00:00:00:00:00','0','0'):
		return False
	else :
		return True


def layer3_detection(device_values,pyt_src,pyt_dst):
	dict = device_values[1]
	src_child = list(pyt_src.children(dict['src_ip']))
	src_paren = list(pyt_src.parent(dict['src_ip']))
	dst_child = list(pyt_dst.children(dict['dst_ip']))
	dst_paren = list(pyt_dst.parent(dict['dst_ip']))
	src_all = src_child + src_paren
	dst_all = dst_child + dst_paren
	src_conflict_rules = []
	for i in src_all:
		i = str(i)
		src_conflict_rules.append(pyt_src[i])
	dst_conflict_rules = []
	for i in dst_all:
		dst_conflict_rules.append(pyt_dst[i])
	print src_conflict_rules
	print dst_conflict_rules
 
def detection(device_values,pyt_src,pyt_dst):
	print("Hello detection starts from here")
	for i in range(0,7):
		if check_layer2_layer4(device_values,i) == True :
			print("No  Recon %s" %(i+1))
		else :
			print("Reconcile %s" %(i+1))
	layer3_detection(device_values,pyt_src,pyt_dst)


if __name__ == "__main__" :
	device_values = creating_dict()
	pyt_src,pyt_dst = p_trie.patricia(device_values)
	detection(device_values,pyt_src,pyt_dst)	
#	print "\nIn Main"	print list(pyt_src)	print list(pyt_dst)	
		

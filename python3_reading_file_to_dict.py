#!/usr/bin/env python
import csv
import sys
import pprint
# Function to convert a csv file to a list of dictionaries.  Takes in one variable called "variables_file"
def csv_dict_list(variables_file):
# Open variable-based csv, iterate over the rows and map values to a list of dictionaries containing key/value pairs
	dict_list = []
	with open(variables_file, newline='') as csvfile:
		reader = csv.DictReader(csvfile)
		for row in reader:
			dict_list.append(row)	
	return dict_list

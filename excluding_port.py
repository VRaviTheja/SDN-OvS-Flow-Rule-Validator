import ipaddress

def func_exclude_port(super_list,sub_list):
	super_list=[x for x in super_list if x not in sub_list]
	return super_list



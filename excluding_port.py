import ipaddress

def func_exclude_port(super_list,sub_list):
	print(len(sub_list))
	if len(super_list) == len(sub_list):
		return [super_list]
	else:
		if sub_list[0] == super_list[0]:
			f_index = super_list.index(sub_list[-1])
			l_list = super_list[f_index + 1 :]
#			print([l_list])
			return [l_list]
		elif sub_list[-1] == super_list[-1]:
			f_index = super_list.index(sub_list[0])
			l_list = super_list[: f_index]
#			print([l_list])
			return [l_list]
		else:
			f_index = super_list.index(sub_list[0])
			l_list1 = super_list[:f_index]
			f_index = super_list.index(sub_list[-1])
			l_list2 = super_list[f_index + 1 :]
#			print([l_list1,l_list2])
			return [l_list1,l_list2]



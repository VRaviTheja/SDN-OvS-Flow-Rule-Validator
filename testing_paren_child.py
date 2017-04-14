import pytricia

def find_all_parents(pyt,ip):
        parent_all = []
	print ip
	ip = pyt.parent(ip)
        while ip != None :
                parent_all.append(ip)
		ip = pyt.parent(ip)
	return parent_all

pyt = pytricia.PyTricia()
pyt["10.1.1.0/8"] = 'a'
pyt["10.1.1.0/16"] = 'b'
pyt.insert("10.1.1.0/24", "c")
print pyt.children('10.1.0.0/8')
print pyt.children('10.1.0.0/16')
print pyt.parent('10.1.1.0/24')
print pyt.parent(pyt.parent('10.1.1.0/24'))
print pyt.parent(pyt.parent(pyt.parent('10.1.1.0/24')))
print pyt.parent('10.0.0.0/8')
parent_all = find_all_parents(pyt,'10.1.1.0/24')
print parent_all

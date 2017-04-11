
#!/usr/bin/python

import pytricia

def patricia(mydict):
	pyt_src = pytricia.PyTricia()
	pyt_dst = pytricia.PyTricia()
	dict = {}
	for dict in mydict:
		check_exact_proceed( dict['src_ip'],dict['dst_ip'],int(dict['aasno']),pyt_src,pyt_dst )

#Listing Patricia Source Trie
        print "Layer 3      --source"
        print list(pyt_src)
        print "\n"
#Listing Patricia Destination Trie
        print "Layer 3 --Destination"
        print list(pyt_dst)
        print "\n"

#Finding Length
        print len(pyt_src)
        print len(pyt_dst)
	print "Source-----"
        for item in pyt_src :
                print (item,pyt_src[item])
	print "Destination-"
        for item in pyt_dst :
                print (item,pyt_dst[item])
	print "Patricia tree formation completed"	
	finding_parent_children(pyt_src,pyt_dst)
        return pyt_src,pyt_dst

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
def finding_parent_children(pyt_src,pyt_dst):
	print "Source-----"
        for item in pyt_src :
		print "children of :"
                print (item,pyt_src[item])
		print pyt_src.children(item)
		print pyt_src.parent(item)
        print "Destination-"
        for item in pyt_dst :
		print "children of :"
                print (item,pyt_dst[item])
		print pyt_dst.children(item)
                print pyt_dst.parent(item)

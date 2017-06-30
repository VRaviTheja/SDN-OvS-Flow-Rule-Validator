import random
import os
import csv
import random_flow_generator
import random_ports
import random_actions
import random_nwport
import random_priority

port_src_start, port_src_end, port_dst_start, port_dst_end = random_ports.port_generator()
src_ip = random_flow_generator.flowgen()
dst_ip = random_flow_generator.flowgen()
action = random_actions.random_action()
nwportno = random_nwport.nw_port()
priority = random_priority.prio()

currentPath = os.getcwd()
csv_file = currentPath + "/csv/Outputflows.csv" 
with open(csv_file, "wb") as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        i = 0
        data = [['aasno','priority','ingress','src_mac','dst_mac','src_ip','dst_ip','src_start','src_end','dst_start','dst_end','nw_proto','action '],[str(i+1),str(priority[i]),str(3),'00:00:00:00:00:00','00:00:00:00:00:00',str(src_ip[i]),str(dst_ip[i]),str(port_src_start[i]),str(port_src_end[i]),str(port_dst_start[i]),str(port_dst_end[i]),nwportno[i],action[i]]]
        i = 1
        for line in data:
            writer.writerow(line)
            if i != 1000:
                data.append([str(i+1),str(priority[i]),str(3),'00:00:00:00:00:00','00:00:00:00:00:00',str(src_ip[i]),str(dst_ip[i]),str(port_src_start[i]),str(port_src_end[i]),str(port_dst_start[i]),str(port_dst_end[i]),nwportno[i],action[i]])
                i = i+1

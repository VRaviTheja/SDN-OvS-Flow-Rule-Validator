import excluding_ip.py
import excluding_port.py
import add_all_rules_after_excluding.py
import ip_address

def conflict_resolver(pyt_src, pyt_dst, mydict, gamma, conflict_type, src_intersection_part, dst_intersection_part, src_port_intersection_part, dst_port_intersection_part):
        if(conflict_type=="shadowing" or conflict_type=="redundancy"):
                print "No need to add rule Shadowing and redundancy"

        elif(conflict_type=="redundancy1"): #changed
                delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
                add_rule_to_patricia(pyt_src, pyt_dst, mydict)
                add_rule_to_newft(mydict)

        elif(conflict_type=="generalization"):
                src_ip_list=excluding_ip.func_exclude_ip(mydict["src_ip"],src_intersection_part)
                dst_ip_list=excluding_ip.func_exclude_ip(mydict["dst_ip"],dst_intersection_part)
                src_port_list=excluding_port.func_exclude_port(list(range(int(mydict["src_start"]),int(mydict["src_end"]))),src_port_intersection_part)
                dst_port_list=excluding_port.func_exclude_port(list(range(int(mydict["dst_start"]),int(mydict["dst_end"]))),dst_port_intersection_part)
                add_all_rules_after_excluding.add_all_rules(src_ip_list)
                add_all_rules_after_excluding.add_all_rules(dst_ip_list)
                add_all_rules_after_excluding.add_all_rules(src_port_list)
                add_all_rules_after_excluding.add_all_rules(dst_port_list)

        elif(conflict_type=="overlap"):
                a=raw_input('Overlap conflict. Choose one flow rule : ')
                if(a=="gamma"):
                        print "No need to add rule"
                else :
                        delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
                        add_rule_to_patricia(pyt_src, pyt_dst, mydict)
                        add_rule_to_newft(mydict)
                print "Resolved Overlap:"
#               print "Do union here"  #union operation

        elif(conflict_type=="correlation"):
                a=raw_input('Correlation conflict. Choose one flow rule : ')
                if(a=="gamma"):
                        print "No need to add rule"
                else :
                        delete_rule_from_pt_ft(pyt_src, pyt_dst, gamma)
                        add_rule_to_patricia(pyt_src, pyt_dst, mydict)
                        add_rule_to_newft(mydict)
                print "Resolved correlation:"

        elif(conflict_type=="imbrication"):
                a=raw_input('Cross layer conflict. Choose one flow rule : ')
                if(a=="gamma"):
                        print "No need to add rule"
                else :
                        add_rule_to_patricia(pyt_src, pyt_dst, mydict)
                        add_rule_to_newft(mydict)
                print "Resolved Imbrication:"




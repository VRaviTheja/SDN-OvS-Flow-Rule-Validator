import random
def nw_port():
    action_lst = []
    lim = 1000
    for _ in range(lim):
        k = random.randint(0, 1)
        if(k==0):
            action_lst.append('6')
        else:
            action_lst.append('1')
    return action_lst

import random
def random_action():
    action_lst = []
    lim = 1000
    for _ in range(lim):
        k = random.randint(0, 1)
        if(k==0):
            action_lst.append('Allow')
        else:
            action_lst.append('Deny')
    return action_lst

import random
def prio():
    action_lst = []
    lim = 1000
    for _ in range(lim):
        k = random.randint(1, 201)
        action_lst.append(k)
    return action_lst

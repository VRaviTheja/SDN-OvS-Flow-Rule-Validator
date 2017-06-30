import random

my_list = []

for i in range(1, 100):
    my_list.append(i)
    if i > 50:
        my_list.append(i)

print my_list
print 'Random (sort of) choice: %s' % random.choice(my_list)

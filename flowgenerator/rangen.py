import random
a = []
b = []
first = "10"
second = "50"
iplist = []
c = "."
for x in range(800):
    a.append(random.randint(1,256))
for x in range(800):
    b.append(random.randint(1,256))
dict = {255:8, 254:7, 252:6, 248:5, 240:4, 224:3, 192:2, 128:1, 0:0 }
masks = [255,254,252,252,255,248,248,240,255,240,224,255,255,224,192,192,128,128,0,0,255,255]
masks1 = [255,254,252,252,248,248,240,255,240,224,224,192,192,128,255]
for x in range(800):
    temp = random.choice(masks)
    a1 = a[x] & temp
    if temp == 255:
        temp1 = random.choice(masks1)
        b1 = b[x] & temp1
        subnet = 24 + dict[temp1]
    else:
        b1 = 0
        subnet = 16 + dict[temp]
    iplist.append(c.join([first, second, str(a1), str(b1)]) + "/" + str(subnet))
for x in range(200):
    c.append(random.randint(1,256))
for x in range(200):
    c.append(random.randint(1,256))
for x in range(200):
    iplist.append(c.join([str(a[x]), str(b[x]), str(c[x]), str(d[x])] + "/32")
for x in range(1000):
	print iplist[x]

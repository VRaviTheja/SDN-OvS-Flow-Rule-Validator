import random
import socket
import struct
from random import randint

def port_generator():
    lim=1000
    port_src_start = []
    port_src_end = []
    port_dst_start = []
    port_dst_end = []

    for i in range (0,lim):
        m = random.randint(1, 200)
        n = random.randint(1, 200)
        if (m<n and m!=n):
            port_src_start.append(m)
            port_src_end.append(n)
        elif (n<m and m!=n):
            port_src_start.append(n)
            port_src_end.append(m)
    while(lim!=len(port_src_start)):
        m = random.randint(1, 200)
        n = random.randint(1, 200)
        if (m<n and m!=n):
            port_src_start.append(m)
            port_src_end.append(n)
        elif (n<m and m!=n):
            port_src_start.append(n)
            port_src_end.append(m)

    for i in range (0,lim):
        k = random.randint(1, 200)
        p = random.randint(1, 200)
        if (k<p and k!=p):
            port_dst_start.append(k)
            port_dst_end.append(p)
        elif (p<k and k!=p):
            port_dst_start.append(p)
            port_dst_end.append(k)
    while(lim!=len(port_dst_start)):
        m = random.randint(1, 200)
        n = random.randint(1, 200)
        if (k<p and k!=p):
            port_dst_start.append(k)
            port_dst_end.append(p)
        elif (p<k and k!=p):
            port_dst_start.append(p)
            port_dst_end.append(k) 
    return (port_src_start, port_src_end, port_dst_start, port_dst_end)

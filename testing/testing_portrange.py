from port_range import PortRange
pr = PortRange('1027/15')
print(pr.bounds)
pr = PortRange('4242-42')
print(pr)

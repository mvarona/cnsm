import sys
print(sys.path)
sys.path.append("/home/dkproxy/.local/bin")
print(sys.path)

from scapy.all import *

from scapy.all import *
def handler(packet):
  print(packet.summary())
sniff(iface="enp61s0", prn=handler, store=0)

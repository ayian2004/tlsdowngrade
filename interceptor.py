from netfilterqueue import NetfilterQueue
from scapy.all import *

nfQueueID         = 0
maxPacketsToStore = 100

def packetReceived(pkt):
  print("Accepted a new packet...")
  ip = IP(pkt.get_payload())
  if not ip.haslayer("Raw"):                               # not the Handshake, forward
    pkt.accept();
  else:
    tcpPayload = ip["Raw"].load;                           # "Raw" corresponds to the TCP payload

    if tcpPayload[0] == 0x16 and tcpPayload[1] == 0x03 and tcpPayload[46] == 0x00 and tcpPayload[47] == 0x35:
      pkt.drop();                                          # drop TLS_RSA_WITH_AES_256_CBC_SHA
    else:
      pkt.accept();                                        # not the Handshake, forward

print("Binding to NFQUEUE", nfQueueID)
nfqueue = NetfilterQueue()
nfqueue.bind(nfQueueID, packetReceived, maxPacketsToStore) # binds to queue 0, use handler "packetReceived()"
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('Listener killed.')

nfqueue.unbind()

from scapy.all import sniff, IP, TCP
from collections import Counter
import logging

logging.basicConfig(filename='alerts_network.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

IP_tries = Counter()

def packet_analysing(PKT):
    if PKT.haslayer(IP) and PKT.haslayer(TCP):
        IP_origin = PKT[IP].src
        port_dest = PKT[TCP].dport

        if port_dest in [21, 23, 80]:
            msg = f"WARNING: Insecure service detected (Port) {port_dest}) comes from {IP_origin}"
            print(msg)
            logging.info(msg)

        if PKT[TCP].flags == 0x02:
            IP_tries[IP_origin] += 1
            if IP_tries[IP_origin] > 10:
                msg = f"WARNING: Possible Port Scan detected coming from {IP_origin}"
                if IP_tries[IP_origin] == 11:
                    print(msg)
                    logging.info(msg)

print("Monitoring the newtork... (Press Ctrl+C to stop)")
sniff(filter="ip", prn=packet_analysing, store=0)
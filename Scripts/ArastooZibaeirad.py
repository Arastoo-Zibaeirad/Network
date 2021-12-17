from scapy.all import *
import socket
from scapy.layers.inet import TCP, IP, UDP, ICMP
import csv
import dpkt
from functools import reduce
import socket
import statistics

collectortcp = []
collectorudp = []
collectoricmp = []
total = []
sourceip = []
destinationip = []
sourceport = []
destinationport = []
proto = []
bytesin = []
bytesout = []



def dumpFlow(flows, flow):
    print(f'Data for flow: {flow}:')
    bytes = reduce(lambda x, y: x+y,
                   map(lambda e: e['byte_count'], flows[flow]))
    packets = reduce(lambda a, z: a+z,
                    map(lambda e: e['packet_count'], flows[flow]))
    Flow_protocol = sorted(map(lambda e: e['protocol'], flows[flow]))
    Flow_protocol = (Flow_protocol[0])
    duration = sorted(map(lambda e: e['ts'], flows[flow]))
    duration = duration[-1] - duration[0]
    print(f"\tTotal Bytes: {bytes}")
    print(f"\tTotal Number of Packets per flow: {packets}")
    print(f"\tAverage Bytes: {bytes / len(flows[flow])}")
    print(f"\tTotal Duration: {duration}")
    print(f"\tMean Packets: {packets / 2}")
    print(f"\tFlow Protocol: {Flow_protocol}")


def packet_capturing(pkt):
    # TCP
    if pkt.haslayer(TCP):
        # TCP Incoming packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(
                f"{str(pkt[IP].src)}:{str(pkt.sport)} ---> {str(pkt[IP].dst)}:{str(pkt.dport)}, TCP, {len(pkt[TCP])} Bytes IN, {pkt.time} time")
            Number_of_Bytes_sent_per_Flow_tcp = f"{len(pkt[TCP])}"

            # return str(pkt[IP].src), pkt[IP].dst, str(pkt.sport), str(pkt.dport), 'TCP', len(pkt[TCP])
        # TCP Outgoing packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(
                f"{str(pkt[IP].src)}:{str(pkt.sport)} ---> {pkt[IP].dst}:{str(pkt.dport)}, TCP, {len(pkt[TCP])} Bytes OUT, {pkt.time} time ")
            Number_of_Bytes_received_per_Flow_tcp = int(len(pkt[TCP]))
            collectortcp.append(Number_of_Bytes_received_per_Flow_tcp)

        sourceip.append(str(pkt[IP].src))
        destinationip.append(str(pkt[IP].dst))
        sourceport.append(str(pkt.sport))
        destinationport.append(str(pkt.dport))
        proto.append('TCP')
        bytesin.append(str(len(pkt[TCP])))
        bytesout.append(str(len(pkt[TCP])))
        protocol = "TCP"
    # UDP
    if pkt.haslayer(UDP):
        # UDP Incoming packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(f"{str(pkt[IP].src)}:{str(pkt.sport)} ---> {pkt[IP].dst}:{str(pkt.dport)}, UDP, {len(pkt[UDP])} Bytes IN ")
            Number_of_Bytes_sent_per_Flow_udp = f"{len(pkt[UDP])}"

        # UDP Outgoing packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(
                f"{str(pkt[IP].src)}:{str(pkt.sport)} ---> {pkt[IP].dst}:{str(pkt.dport)}, TCP, {len(pkt[UDP])} Bytes OUT ")
        Number_of_Bytes_received_per_Flow_udp = f"{len(pkt[UDP])}"
        collectorudp.append(Number_of_Bytes_received_per_Flow_udp)

        sourceip.append(str(pkt[IP].src))
        destinationip.append(str(pkt[IP].dst))
        sourceport.append(str(pkt.sport))
        destinationport.append(str(pkt.dport))
        proto.append('UDP')
        bytesin.append(str(len(pkt[UDP])))
        bytesout.append(str(len(pkt[UDP])))
        protocol = "UDP"

    # ICMP
    if pkt.haslayer(ICMP):
        # ICMP Incoming packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(
                f"{str(pkt[IP].src)}:{str(pkt.sport)} ---> {pkt[IP].dst}:{str(pkt.dport)}, ICMP, {len(pkt[ICMP])} Bytes IN ")
            Number_of_Bytes_sent_per_Flow_icmp = f"{len(pkt[ICMP])}"

        # ICMP Outgoing packets
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(
                f"{str(pkt[IP].src)}:{str(pkt.sport)} ---> {pkt[IP].dst}:{str(pkt.dport)}, ICMP, {len(pkt[ICMP])} Bytes OUT ")
            Number_of_Bytes_received_per_Flow_icmp = f"{len(pkt[ICMP])}"
        collectoricmp.append(Number_of_Bytes_received_per_Flow_icmp)

        sourceip.append(str(pkt[IP].src))
        destinationip.append(str(pkt[IP].dst))
        sourceport.append(str(pkt.sport))
        destinationport.append(str(pkt.dport))
        proto.append('ICMP')
        bytesin.append(str(len(pkt[ICMP])))
        bytesout.append(str(len(pkt[ICMP])))
        protocol = "ICMP"


if __name__ == '__main__':
    sniff(prn=packet_capturing)
    dumpFlow()
    x = 0
    for i in collectortcp:
        x += int(i)

    y = 0
    for j in collectorudp:
        y += int(j)

    z = 0
    for t in collectoricmp:
        z += int(t)

    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@1", sourceip)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@2", destinationip)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@3", sourceport)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@4", destinationport)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@5", proto)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@6", bytesin)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@7", bytesout)
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@8", len(sourceport))
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@9", len(bytesin))
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@10", len(bytesout))

    Total_Bytes_used_for_Headers_in_the_Forward_Direction = x + y + z
    print("Total_Bytes_used_for_Headers_in_the_Forward_Direction: ",
          Total_Bytes_used_for_Headers_in_the_Forward_Direction)

    header = ['SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'Flow\'sProtocol',
              'Number of Bytes Sent per Flow', 'Number of Bytes received per Flow',
              'Total Bytes used for Headers in the Forward Direction']
    for i in range(len(sourceip)):
        data = array(sourceip[i], destinationip[i], sourceport[i], destinationport[i], proto[i], bytesin[i], bytesout[i],
                Total_Bytes_used_for_Headers_in_the_Forward_Direction[i])
        
    with open('output.csv', 'w') as output:
        writer = csv.writer(output)
        writer.writerow(header)
        writer.writerow(data)

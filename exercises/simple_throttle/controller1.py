from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
import ipaddress

import sys

MIRROR_SESSION_ID = 99

topo = Topology(db="topology.db")
switchName="s1" 
thrift_port = topo.get_thrift_port(switchName)
cpu_port = topo.get_cpu_port_index(switchName)
controller = SimpleSwitchAPI(thrift_port)
controller.mirroring_add(MIRROR_SESSION_ID, cpu_port)


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField("fid", 0, 32),BitField("contracted", 0, 32),BitField("incomming", 0, 32), BitField("srcIP", 0, 32),BitField("dstIP", 0, 32), BitField("srcP", 0, 16),BitField("dstP", 0, 16)]

def msg_receive(pkt):
    packet = Packet(str(pkt)) 
    ethernet_frame = ethernet_frame = Ether(str(packet))   
    ip_packet = ethernet_frame.payload    
    cpu_header = CpuHeader(str(ip_packet.payload)) 


    fid=cpu_header.fid
    contracted=cpu_header.contracted
    incomming=cpu_header.incomming
    srcIP=cpu_header.srcIP
    dstIP=cpu_header.dstIP
    srcP=cpu_header.srcP
    dstP=cpu_header.dstP
    
    print("flow id is "+ str(fid))
    print("contracted  is "+ str(contracted))
    print("incomming is "+ str(incomming))
    print("source IP is "+ str(ipaddress.IPv4Address(srcIP)))
    print("destination IP is "+ str(ipaddress.IPv4Address(dstIP)))
    print("source Port is "+ str(srcP))
    print("destination Port is "+ str(dstP))
    

    if incomming==0:
        incomming=1
    div=(contracted*1.0)/(incomming)
    print("div is "+ str(div))
    if div<0:
        div=0
    if div>1:
        div=1
    drop_rate=(1-div)*100

    """
    100%       35
    drop_rate  x

    x=(drop_rate*35)/100

    """
    x=(drop_rate*30)/100
    
    print("drop rate has been set to " + str(x)+ " which is "+str(drop_rate)+" percentage")
    drop_rate=x
        
    
    print("drop rate "+ str(drop_rate))
    controller.register_write("MyIngress.dropRates", str(fid), drop_rate)

    for x in range(10):
        print(controller.register_read("MyIngress.dropRates", x)),
    print("\n\n")

def resetDropRate(index):
    if index =="all":
        for item in range(10):
            controller.register_write("MyIngress.dropRates", str(item), 0)
            print("flow "+str(item)+" drop rate has been set to 0")
        print("all flow drop rates have been set to 0")
    else:
        controller.register_write("MyIngress.dropRates", str(index), 0)
        print("flow "+str(index)+" drop rate has been set to 0")


if __name__ == "__main__":
    action=sys.argv[1]
    if action == "dynamicDR":
        sniff(iface="s1-cpu-eth1", prn=msg_receive)
    elif action == "resetDR":
        index = sys.argv[2]
        resetDropRate(index)
        
    
    

     

   

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
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
    fields_desc = [BitField("fid", 0, 32),BitField("contracted", 0, 32),BitField("incomming", 0, 32)]

def msg_receive(pkt):
    packet = Packet(str(pkt)) 
    ethernet_frame = ethernet_frame = Ether(str(packet))   
    ip_packet = ethernet_frame.payload    
    cpu_header = CpuHeader(str(ip_packet.payload)) 

    fid=cpu_header.fid
    contracted=cpu_header.contracted
    incomming=cpu_header.incomming
    
    print("flow id is "+ str(fid))
    print("contracted  is "+ str(contracted))
    print("incomming is "+ str(incomming))
    if incomming==0:
        incomming=1
    div=(contracted*100)/incomming
    if div<0:
        div=0
    if div>100:
        div=100
    drop_rate=100-div
    print("drop rate "+ str(drop_rate))
    controller.register_write("MyIngress.dropRates", str(fid), 20)

    for x in range(10):
        print(controller.register_read("MyIngress.dropRates", x)),
    print("")

if __name__ == "__main__":
    sniff(iface="s1-cpu-eth1", prn=msg_receive)
    

     

   

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
    fields_desc = [BitField("fid", 0, 32)]

def msg_receive(pkt):
    packet = Packet(str(pkt)) 
    ethernet_frame = ethernet_frame = Ether(str(packet))   
    ip_packet = ethernet_frame.payload    
    cpu_header = CpuHeader(str(ip_packet.payload)) 
    
    print("flow id is "+ str(cpu_header.fid))
    controller.register_write("MyIngress.dropRates", str(cpu_header.fid), 20)

    for x in range(10):
        print(controller.register_read("MyIngress.dropRates", x))
  

if __name__ == "__main__":
    sniff(iface="s1-cpu-eth1", prn=msg_receive)
    

     

   

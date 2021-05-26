from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField

MIRROR_SESSION_ID = 99

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('fid', 0, 32)]

def msg_receive(pkt):
    packet = Packet(str(pkt)) 
    cpu_header = CpuHeader(bytes(packet.payload))
    print(str(cpu_header.fid))


if __name__ == "__main__":
    import sys
    topo = Topology(db="topology.db")
    switchName="s1" 
    thrift_port = topo.get_thrift_port(switchName)
    cpu_port = topo.get_cpu_port_index(switchName)
    controller = SimpleSwitchAPI(thrift_port)

   
    controller.mirroring_add(MIRROR_SESSION_ID, cpu_port)
    print("mirrored")
    
    sniff(iface="s1-cpu-eth1", prn=msg_receive)
    

     

   

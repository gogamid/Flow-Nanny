import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw
import ipaddress
import sys


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('flowid',0,32)]


class L2Controller(object):

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        self.init()

    def init(self):
        self.controller.reset_state()
        self.add_mirror()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(99, self.cpu_port)

    def recv_msg_cpu(self, pkt):
        # packet = Packet(str(pkt))
        # ethernet_frame = Ether(str(packet))
        # # ip_packet = ethernet_frame.payload
        # # cpu_header = CpuHeader(str(ip_packet.payload))
        print("FlowId is here: " + str(raw(pkt)))

    def run_cpu_port_loop(self):
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)


if __name__ == "__main__":
    controller = L2Controller("s1").run_cpu_port_loop()


#Problem 1 
#Ping fails when used with controller

#Problem 2
#extract Ip ethernet cpu header separetaly 

#Problem 3
#I wanted to fill out AZD, but there is no AZD for November. Copy paste of other months are not possible
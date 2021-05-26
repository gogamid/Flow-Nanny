from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField


MIRROR_SESSION_ID = 100
L2_LEARN_ETHER_TYPE = 0x4221


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('fid', 0, 32)]


class LearningSwitchControllerApp(object):

    def __init__(self, switchName):
        self.topo = Topology(db="topology.db")
        self.switchName = switchName
        self.thrift_port = self.topo.get_thrift_port(switchName)
        self.cpu_port = self.topo.get_cpu_port_index(self.switchName)
        self.controller = SimpleSwitchAPI(self.thrift_port)

        self.init()
        print("initialised")

    def init(self):
        self.controller.reset_state()
        self.add_mirror()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(MIRROR_SESSION_ID, self.cpu_port)
        print("mirrored")

    def recv_msg_cpu(self, pkt):
        print("message received")
        
        # self.controller.register_write(
        # "MyIngress.dropRates", cpu_header.fid, 15)

    def run_cpu_port_loop(self):
        print("loop has started")
        cpu_port_intf = str(self.topo.get_cpu_port_intf(
            self.switchName).replace("eth0", "eth1"))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)


if __name__ == "__main__":
    import sys
    switchName = sys.argv[1]
    controller = LearningSwitchControllerApp(switchName).run_cpu_port_loop()

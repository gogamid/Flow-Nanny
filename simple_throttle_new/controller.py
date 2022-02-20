import nnpy
import struct
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from scapy.all import Ether, sniff, Packet, BitField, raw
import ipaddress
import sys
import sched, time
s = sched.scheduler(time.time, time.sleep)

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('flowid',0,32), BitField('flowBytes',0,32), BitField('portBytes',0,32)]


class L2Controller(object):

    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)
        self.init()
        self.heavyHitterFlowIds = []
        self.defaultDropRate = 10
        self.isNotSetBefore = True

    def resetDropRatesAfterEachInterval(self, sc): 
        print("***************Resetting drop rates**************\n")
        for item in range(10):
            self.controller.register_write("MyIngress.dropRates", str(item), 0)
            # self.controller.register_write("MyIngress.isHeavyHitter", str(item), 0)
        s.enter(40, 1, self.resetDropRatesAfterEachInterval, (sc, ))
    
    def printDropRates(self):
        for x in range(10):
            print(str(self.controller.register_read("MyIngress.dropRates", x))),
        

    def init(self):
        self.add_mirror()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(99, self.cpu_port)

    def recv_msg_cpu(self, pkt):
        cpu_header = CpuHeader(raw(pkt))
        print("This flow is heavy hitter: " + str(cpu_header.flowid))
        self.heavyHitterFlowIds.append(str(cpu_header.flowid))
        #only first heavy hitter is dropped to make it testable. In the future there is possibility to extend. 
        if self.heavyHitterFlowIds[0] == str(cpu_header.flowid):
            self.defaultDropRate+=10
            self.controller.register_write("MyIngress.dropRates", str(cpu_header.flowid), self.defaultDropRate)
            self.controller.register_write("MyIngress.isHeavyHitter", str(cpu_header.flowid), 1)
        self.printDropRates()

    def setDropRate(self, flow_id, drop_rate):
        self.controller.register_write("MyIngress.dropRates", flow_id, int(drop_rate))
        self.printDropRates()


    def run_cpu_port_loop(self):
        s.enter(40, 1, self.resetDropRatesAfterEachInterval, (s, ))
        s.run()
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu)
        


if __name__ == "__main__":
    if len(sys.argv ) < 1:
        print("command: sudo python controller.py run or sudo python controller.py set [flowid][drop rate]")
    else:
        controller = L2Controller("s1")
        action = sys.argv[1] 
        if action == "run":
            controller.run_cpu_port_loop()
        elif action == "set":
            if len(sys.argv ) < 3:
                print("command: sudo python controller.py set [flowid] [dropRate]")
            else:
                fid = sys.argv[2]
                dr = sys.argv[3]
                controller.setDropRate(fid, dr)
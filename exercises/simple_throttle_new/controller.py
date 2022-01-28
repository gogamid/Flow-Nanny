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

    def do_something(self, sc): 
        print("***************Resetting drop rates**************\n")
        for item in range(10):
            self.controller.register_write("MyIngress.dropRates", str(item), 0)
            # self.controller.register_write("MyIngress.isHeavyHitter", str(item), 0)
        s.enter(40, 1, self.do_something, (sc, ))
    
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
        s.enter(40, 1, self.do_something, (s, ))
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

#06.12.2021 Meeting Questions 

#Problem 1 
#Ping fails when used with controller
#-reset state should be commented

#Problem 2
#parse Ip ethernet cpu header separetaly
#parse with raw

#Problem 3
#I wanted to fill out AZD, but there is no AZD for November. Copy paste of other months are not possible
#-contact secretary 

# Next time
# drop rate of 10 calculation in controller

#13.12.2021 Meeting https://github.com/gogamid/P4-Tutorial-and-my-projects/tree/main/exercises/simple_throttle_new
#Overall progress: Dropping works this time properly. Example: All links are bandwidth limited to 1 Mbit/s. When one flow is causing more than 50% of previous portBytes, then if i set drop rate of 90%. Flow gets dropped from 1Mbit/s to 100kbit/s. 

#Problem 0 
#two heavyHitterFlowI sharing one link of 1Mb/s, which is about 500kb/s per each. When I drop one flow lets say 10%. It doesnt affect its performance. Because 10% drop means drop from 1Mb/s of potential bandwidth. I can see the effect when I drop more than 50%. In the example I dropped 90% to see the effect of dropping from potential bandwidth of 1Mb/s to 100kb/s. But in reality, it dropped from 500kbit/s to 100kbit/s. Is that normal behaviour? 
#- makes sense, normal behaviour 


#Problem 1
#Controller is getting port bytes as 0?Maybe port limit or time of link level window or flow level window should be changed? 

#Problem 2
#Drop rate is working, but usually both heavyHitterFlowI are dropped. How to test better that one flow takes advantage of other flow dropping? In detail, when flow can be not heavy hitter again? what is the requirement for that? 
#- only one flow should be dropped. First only drop
#----------------------------------------------------------------------------
#Meetig 12.01.2022
#Next time: 
#change of drop rate during run time. With command line and etc
# or dynamicly depending how many bytes it passed limit
#next time at Wednesday 13:00

#Meetig 19.01.2022
#Next time:
#gradual incrase of drop rate 10 20 30 40 50 
#healing process looks for the flows which are dropped and "behaving well"(less trafic), controller should gradually drop the droprate. 
#binary approach isHeavyHitter then incrase dropRate +10
#reset all droprates after 20 sec

#Meetig 28.01.2022 
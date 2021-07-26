from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField
import ipaddress
import time

import sys

MIRROR_SESSION_ID = 99

topo = Topology(db="topology.db")
switchName = "s1"
thrift_port = topo.get_thrift_port(switchName)
cpu_port = topo.get_cpu_port_index(switchName)
controller = SimpleSwitchAPI(thrift_port)
controller.mirroring_add(MIRROR_SESSION_ID, cpu_port)

# parses the cpu header


class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField("fid", 0, 32), BitField("contracted", 0, 32), BitField("incomming", 0, 32), BitField(
        "srcIP", 0, 32), BitField("dstIP", 0, 32), BitField("srcP", 0, 16), BitField("dstP", 0, 16)]

# prints out all drop rates from register


def printDropRates(maxFlows):
    for x in range(maxFlows):
        print(controller.register_read("MyIngress.dropRates", x)),


def printHH(maxFlows):
    for x in range(maxFlows):
        print(controller.register_read("MyIngress.isHeavyHitter", x)),


def printLinkLoad(ports):
    for x in range(ports):
        print(controller.register_read("MyIngress.linkLoad", x)),


def printBytesReceived(maxFlows):
    for x in range(maxFlows):
        print(controller.register_read("MyIngress.bytesReceived", x)),

def printBytesReceivedPort(maxFlows):
    for x in range(maxFlows):
        print(controller.register_read("MyIngress.bytesReceivedPort", x)),

# calculates drop rate for the flow with contracted and incomming


def calculateDropRate(incomming, contracted):
    # we cannot devide to 0
    if incomming == 0:
        incomming = 1

    # division needed for the algorithm
    div = (contracted*1.0)/(incomming)
    print("div is " + str(div))

    # div cannot be negative, otherwise drop rate is higher than 100%
    if div < 0:
        div = 0

    # div cannot be more than 1, otherwise drop rate is less than 0%
    if div > 1:
        div = 1

    # main algorithm derived from Lucas Fernandes
    return (1-div)*100


# this function receives the message from data plane.
# It parses all the headers and saves the elements of cpu header to local variables.
# With the help of those variables dynamic drop rates is calculated:
#     DROP RATE=(1-contracted/incomming)*100;

def msg_receive(pkt):
    packet = Packet(str(pkt))
    ethernet_frame = ethernet_frame = Ether(str(packet))
    ip_packet = ethernet_frame.payload
    cpu_header = CpuHeader(str(ip_packet.payload))

    fid = cpu_header.fid
    contracted = cpu_header.contracted
    incomming = cpu_header.incomming
    srcIP = cpu_header.srcIP
    dstIP = cpu_header.dstIP
    srcP = cpu_header.srcP
    dstP = cpu_header.dstP

    print("flow id is " + str(fid))
    print("contracted  is " + str(contracted))
    print("incomming is " + str(incomming))
    print("source IP is " + str(ipaddress.IPv4Address(srcIP)))
    print("destination IP is " + str(ipaddress.IPv4Address(dstIP)))
    print("source Port is " + str(srcP))
    print("destination Port is " + str(dstP))

    drop_rate = calculateDropRate(incomming, contracted)

    # DROP RATE IS NO MORE THAN 30 FOR TESTING PURPOSES
    x = (drop_rate*30)/100
    print("drop rate has been set to " + str(x) +
          " which is "+str(drop_rate)+" percentage")
    drop_rate = x

    print("drop rate " + str(drop_rate))
    controller.register_write("MyIngress.dropRates", str(
        fid), drop_rate)  # write to the register
    printDropRates(10)
    print("\n\n")


# this function is for setting drop rates of flows to 0
# it can set either all flows or just index out of [0,9]

def resetDropRate(index):
    if index == "all":
        for item in range(10):
            controller.register_write("MyIngress.dropRates", str(item), 0)
            controller.register_write("MyIngress.isHeavyHitter", str(item), 0)
            print("flow "+str(item)+" drop rate has been set to 0")
        print("all flow drop rates have been set to 0")
    else:
        controller.register_write("MyIngress.dropRates", str(index), 0)
        print("flow "+str(index)+" drop rate has been set to 0")


if __name__ == "__main__":

    action = sys.argv[1]

    # first program to calculate the drop rate. It need just 1 argument
    if action == "dynamicDR":
        sniff(iface="s1-cpu-eth1", prn=msg_receive)

    # second program to reset the drop rate. It need just 2 arguments, second one is "all" or indexnumber
    elif action == "resetDR":
        index = sys.argv[2]
        resetDropRate(index)

    elif action == "stats":
        # c=0
        # while True:
        #     c+=1
        # print("\n******STAT NUMBER "+str(c)+"********")
        # print("Link Load per port currently:")
        # printLinkLoad(3)
        # print("\nPrev Bytes Count per port currently:")
        # printBytesReceivedPort(3)
        # print("\nBytes Received Per Flow currently:")
        # printBytesReceived(10)
        print(controller.register_read("MyIngress.whitelistedFlow", 0 ))
        print("\nDrop Rates are currently:")
        printDropRates(10)
        print("\nHeavy Hitters are:")
        printHH(10)

        # time.sleep(3)
    elif action == "set":
        index = sys.argv[2]
        controller.register_write("MyIngress.dropRates", str(index), 20)
         controller.register_write("MyIngress.isHeavyHitter", str(index), 1)
    elif action == "reset":
        index = sys.argv[2]
        controller.register_write("MyIngress.dropRates", str(index), 0)
        controller.register_write("MyIngress.isHeavyHitter", str(index), 0)



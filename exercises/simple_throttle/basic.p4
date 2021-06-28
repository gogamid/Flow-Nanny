/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<16> TYPE_IPV4 = 0x800;

// const bit<48> window=1000000; //frequency that we reset the bytes received, in microseconds(1s)
// const bit<32> contracted=100; //limit of bytes allowed during the time "window"
const bit<32> maxFlows=10; //number of flows supported for now
const bit<32> portBasedByteLimit=100;    //in the given window
const bit<48> flow_level_window=1000000; //frequency that we reset the bytes received, in microseconds(1s)



// const bit<32> MIRROR_SESSION_ID = 99; //for cpu header

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
// // cpu header  to be sent to the controller (24 Bytes)
// header cpu_t {
//     bit<32> flowid;
//     bit<32> contracted;
//     bit<32> incomming;
//     bit<32> srcIP;
//     bit<32> dstIP;
//     bit<16> srcP;
//     bit<16> dstP;

// }

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

//only ports needed for the hash so no differentiation between TCP und UDP
struct l4_ports_t {
    bit<16> src_port;
    bit<16> dst_port;
}

struct metadata {
    l4_ports_t l4_ports;
    // bit<32> flowid;
    // bit<32> contracted;
    // bit<32> incomming;
    // bit<32> srcIP;
    // bit<32> dstIP;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    // cpu_t        cpu;
}



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
         transition select(hdr.ipv4.protocol){
            TYPE_TCP: port_parse;
            TYPE_UDP: port_parse;
            default: accept;
        }
    }
    state port_parse{
        meta.l4_ports = packet.lookahead<l4_ports_t>();
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { 
         verify_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16); 

    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

   
    bit<32> flowId; //calculated in get_flowId() function and used as an index for registers
    bit<1> _isSeen; //local help variable which is used with register "isSeen"
    bit<32> incomming; //local help variable which is used with register "bytesReceived"
    bit<48> _startTime; //local help variable which is used with register "startTime"
    bit<32> link_load;

    register<bit<48>>(maxFlows) startTime; //start time of flows with index of flowId
    register<bit<32>>(maxFlows) bytesReceived; //number of bytes received per flow
    register<bit<32>>(maxFlows) dropRates; //drop rates per flow level which are calculated in controller
    register<bit<1>>(maxFlows) isSeen; //in order to identify first packet in the flow(0 first Packet, 1 not)
    register<bit<32>>(maxFlows) packets_dropped; //counters for number of drops per flow level 
    register<bit<1>>(maxFlows) isHeavyHitter; //in order to undentify heavy hitters
    register<bit<32>>(3) linkLoad; //works on poort 1,2,3 level

    /*
    this function drops the packet and increases the counter for dropped packets per flow
    */
   action drop() {
        mark_to_drop(standard_metadata);

        //calculate packets dropped per flow
        bit<32> dropped;
        packets_dropped.read(dropped, flowId);
        packets_dropped.write(flowId, dropped+1);
    }
    /*
    this function calculates hash value from 5 Tuple and assigns to local variable "flowid".
    Additionally saves some information in meta
    */
    action get_flowId(){
        hash(flowId, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr,hdr.ipv4.dstAddr, meta.l4_ports.src_port, meta.l4_ports.dst_port, hdr.ipv4.protocol}, maxFlows);
        // meta.flowid=flowId;
        // meta.srcIP=hdr.ipv4.srcAddr;
        // meta.dstIP=hdr.ipv4.dstAddr;
     }

    /*
    this function does simple forwarding when destination mac address and port is known
    */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }  
    table pkt_forward {
        actions = {
            ipv4_forward;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
    }

    apply {
        pkt_forward.apply();

        get_flowId(); //calculate flow id from 5 tuple and save into flowid
        
        /*Is it a first packet, then note time of ingress. */  //try to run 
        isSeen.read(_isSeen, flowId);
        if(_isSeen==0) {
            startTime.write(flowId, standard_metadata.ingress_global_timestamp);
            isSeen.write(flowId,1);
        }
            
        
        //do these if window  is elapsed 
        startTime.read(_startTime, flowId);
        if(standard_metadata.ingress_global_timestamp - _startTime>=flow_level_window) {
            
            //get tracked linked load
            linkLoad.read(link_load, (bit<32>)standard_metadata.ingress_port);

            if(5*link_load>4*portBasedByteLimit){ //above 80%

                    //get flow byte counter
                    bytesReceived.read(incomming, flowId);

                    if(2*incomming>link_load){ //above 50%
                        //this part can be done in controller 
                        //treat flow as heavy hitter
                        dropRates.write(flowId, 30);

                    }


            } 

            startTime.write(flowId, standard_metadata.ingress_global_timestamp);
            linkLoad.write((bit<32>)standard_metadata.ingress_port,0); //reset link load after window elapses !!!change
            bytesReceived.write(flowId, 0);
        }

        
        //increase bytes received  by packet length port based
        linkLoad.read(link_load,(bit<32>)standard_metadata.ingress_port); //change notice 
        linkLoad.write((bit<32>)standard_metadata.ingress_port, link_load+standard_metadata.packet_length);

        //increase bytes received  by packet length per flow
        bytesReceived.read(incomming,flowId);
        bytesReceived.write(flowId,incomming+standard_metadata.packet_length);


        // //applying probabilistic drop rate if there is
        // bit<32> probability;
        // random<bit<32>>(probability, 32w0, 32w100);    // [0,...,100]
        // bit<32> dropRate;
        // dropRates.read(dropRate, flowId);
        // if (probability <= dropRate) {
        //     drop();
        // }
        
}
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // // if packet was cloned (instance_type == 1)
        // if (standard_metadata.instance_type == 1){
        //     // populate cpu header
        //     hdr.cpu.setValid();
        //     hdr.cpu.flowid = meta.flowid;
        //     hdr.cpu.incomming=meta.incomming;
        //     hdr.cpu.contracted=contracted;
        //     hdr.cpu.srcIP=meta.srcIP;
        //     hdr.cpu.dstIP=meta.dstIP;
        //     hdr.cpu.srcP=meta.l4_ports.src_port;
        //     hdr.cpu.dstP=meta.l4_ports.dst_port;
        //     truncate((bit<32>)58);  // Ether 14 Bytes, IP 20 Bytes  CPU Header (24 bytes)
        // }
      }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
         update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        // packet.emit(hdr.cpu);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
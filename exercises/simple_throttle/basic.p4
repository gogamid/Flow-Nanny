/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

const bit<16> TYPE_IPV4 = 0x800;
const bit<48> window=1000000; //in microseconds 1s=1 000 000 microsec
const bit<32> maxBytes=100; //
const bit<32> maxFlows=10; //number of flows supported for now


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

struct l4_ports_t {
    bit<16> src_port;
    bit<16> dst_port;
}

struct metadata {
    l4_ports_t l4_ports;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
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

   
    bit<32> flowId;
    bit<1> _isSeen;
    bit<32> _byteCnt;
    bit<32> DROP_RATE;
    bit<48> _startTime;
    register<bit<48>>(maxFlows) startTime; //start time of flows with index of flowId
    register<bit<32>>(maxFlows) bytesReceived; //counts bytes per flow
    register<bit<32>>(maxFlows) dropRates; //drop rates are applied in runtime
    register<bit<1>>(maxFlows) isSeen; //0 no, 1 yes
    register<bit<32>>(maxFlows) packets_dropped;

   action drop() {
        mark_to_drop(standard_metadata);

        //note packets dropped per flow
        bit<32> dropped;
        packets_dropped.read(dropped, flowId);
        packets_dropped.write(flowId, dropped+1);
    }
    action get_flowId(){
        hash(flowId, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr,hdr.ipv4.dstAddr, meta.l4_ports.src_port, meta.l4_ports.dst_port, hdr.ipv4.protocol}, maxFlows);
     }

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
    
        //flowid from 5 Tuple
        get_flowId();
    
       
        //is it first packet, then note time of ingress
        isSeen.read(_isSeen, flowId);
        if(_isSeen==0) 
            startTime.write(flowId, standard_metadata.ingress_global_timestamp);
        isSeen.write(flowId,1);

        //is a window reached?
        startTime.read(_startTime, flowId);
        if(standard_metadata.ingress_global_timestamp - _startTime>=window) {

            //reset incoming byte counter
            bytesReceived.write(flowId,0);

            //set start time for flow
            startTime.write(flowId, standard_metadata.ingress_global_timestamp);
        }

        //increase bytes received
        bytesReceived.read(_byteCnt,flowId);
        bytesReceived.write(flowId,_byteCnt+standard_metadata.packet_length);

        //apply probabilistic drop to packets that exceed maxBytes in window
         bytesReceived.read(_byteCnt,flowId);
         if(_byteCnt > maxBytes) {

            //drop decision with probability
            bit<32> probability;
            random<bit<32>>(probability, 32w0, 32w100);    // [0,...,100]
            dropRates.read(DROP_RATE, flowId);
            if (probability <= DROP_RATE) {
                drop();
            }

         }  
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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

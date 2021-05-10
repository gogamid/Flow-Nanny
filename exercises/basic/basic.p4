/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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
struct mp_metadata {
    bit<32> probability_handle;
    bit<32> maxflow_handle;
}
struct metadata {
    mp_metadata meta;
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
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
action_selector(HashAlgorithm.myHash, 32w1024, 32w128) mp_profile;

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

  counter(32w1, CounterType.packets) drop_counter;
   counter(32w8, CounterType.packets) path_counter;
     action count_path(bit<32> path) {
        path_counter.count((bit<32>)path);
    }
    action set_destination(bit<48> dmac, bit<9> port) {
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
    }
     action set_maxflow_handle(bit<32> port) {
        meta.meta.maxflow_handle = port;
    }
     action set_probability_handle(bit<32> port) {
        meta.meta.probability_handle = port;
    }
     action _nop() {
    }
    action _drop() {
        drop_counter.count((bit<32>)32w0);
        mark_to_drop(standard_metadata);
    }
    action set_mp_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
     action set_mp_regular_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
     table mp_count_path {
        actions = {
            count_path;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
    }
     table mp_forward {
        actions = {
            set_destination;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
    }
    table mp_maxflow_meta {
        actions = {
            set_maxflow_handle;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
    }
    table mp_probability_meta {
        actions = {
            set_probability_handle;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
    }
  table mp_profile_forward {
        actions = {
            _nop;
            _drop;
            set_mp_port;
        }
        key = {
            hdr.ipv4.srcAddr            : exact;
            hdr.ipv4.dstAddr            : exact;
            hdr.ipv4.srcAddr            : selector;
            hdr.ipv4.dstAddr            : selector;
            hdr.ipv4.totalLen           : selector;
            meta.meta.maxflow_handle    : selector;
            meta.meta.probability_handle: selector;
        }
        size = 1024;
        implementation = mp_profile;
    }
    table mp_regular_forward {
        actions = {
            set_mp_regular_port;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
    }
   table mp_set_dmac {
        actions = {
            set_dmac;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
    }




    action throttle(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    // table ipv4_lpm {
    //     key = {
    //         hdr.ipv4.dstAddr: lpm;
    //     }
    //     actions = {
    //         ipv4_forward;
    //         drop;
    //         throttle;
    //         NoAction;
    //     }
    //     size = 1024;
    //     default_action = drop();
    // }
    
    apply {
        // if (hdr.ipv4.isValid()) {
        //     ipv4_lpm.apply();
        // }

        mp_probability_meta.apply();
        mp_maxflow_meta.apply();

        mp_set_dmac.apply();

        // mp_profile_forward.apply();
        mp_regular_forward.apply();

        mp_count_path.apply();
        mp_forward.apply();
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

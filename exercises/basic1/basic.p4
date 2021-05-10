/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
struct mp_metadata {
    bit<32> probability_handle;
    bit<32> maxflow_handle;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct metadata {
    /*Annotations controlling naming
Control plane-related annotations (Section 18.3.3) can alter the names exposed to the control plane in
the following ways.
    • The @hidden annotation hides a controllable entity from the control plane. This is the only case in
    which a controllable entity is not required to have a unique, fully-qualified name.
    • The @name annotation may be used to change the local name of a controllable entity.*/
    @name(".meta") 
    mp_metadata meta;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

     @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
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
@name(".mp_profile") action_selector(HashAlgorithm.probabilistic_simple_multipath, 32w1024, 32w128) mp_profile;

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
//   @name(".drop_counter") counter(32w1, CounterType.packets) drop_counter;
//     @name(".path_counter") counter(32w8, CounterType.packets) path_counter;
    @name(".count_path") action count_path(bit<32> path) {
        path_counter.count((bit<32>)path);
    }
    @name(".set_destination") action set_destination(bit<48> dmac, bit<9> port) {
        hdr.ethernet.dstAddr = dmac;
        standard_metadata.egress_spec = port;
    }
    @name(".set_maxflow_handle") action set_maxflow_handle(bit<32> port) {
        meta.meta.maxflow_handle = port;
    }
    @name(".set_probability_handle") action set_probability_handle(bit<32> port) {
        meta.meta.probability_handle = port;
    }
    @name("._nop") action _nop() {
    }
    @name("._drop") action _drop() {
        drop_counter.count((bit<32>)32w0);
        mark_to_drop(standard_metadata);
    }
    @name(".set_mp_port") action set_mp_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    @name(".set_mp_regular_port") action set_mp_regular_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    @name(".set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name(".mp_count_path") table mp_count_path {
        actions = {
            count_path;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
    }
    @name(".mp_forward") table mp_forward {
        actions = {
            set_destination;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
    }
    @name(".mp_maxflow_meta") table mp_maxflow_meta {
        actions = {
            set_maxflow_handle;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
    }
    @name(".mp_probability_meta") table mp_probability_meta {
        actions = {
            set_probability_handle;
        }
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
    }
    @name(".mp_profile_forward") table mp_profile_forward {
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
    @name(".mp_regular_forward") table mp_regular_forward {
        actions = {
            set_mp_regular_port;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
    }
    @name(".mp_set_dmac") table mp_set_dmac {
        actions = {
            set_dmac;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
    }
    apply {
        mp_probability_meta.apply();
        mp_maxflow_meta.apply();
        mp_set_dmac.apply();
        mp_profile_forward.apply();
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

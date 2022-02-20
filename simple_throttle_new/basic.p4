/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> maxFlows=10; //number of flows supported for now

const bit<32> portBasedByteLimit=500000; //limit till 5 Mbit per 5 seconds
const bit<48> link_level_window=5000000 ; //link level window is 5 seconds
const bit<48> flow_level_window=15000000; //flow level window is 15 seconds

const bit<32> MIRROR_SESSION_ID = 99; //for cpu header



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

// cpu header  to be sent to the controller (4 Bytes)
header cpu_t {
    bit<32> flowid;
    bit<32> prevFlowBasedBytesExceeded;
    bit<32> prevPortBasedBytesExceeded;
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

//only ports needed for the hash so no differentiation between TCP und UDP
struct l4_ports_t {
    bit<16> src_port;
    bit<16> dst_port;
}

struct metadata {
    l4_ports_t l4_ports;
    bit<32> flowid;
    bit<32> prevFlowBasedBytesExceeded;
    bit<32> prevPortBasedBytesExceeded;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    cpu_t        cpu;
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
    //registers and local variables
    bit<32> flowId; //calculated in get_flowId() function and used as an index for registers
    bit<32> current_iPort; //ingress port
    bit<32> current_ePort; //egress port

    //for egress 
    bit<1> _isSeenPortEgress; //local help variable which is used with register "isSeenPortEgress"
    register<bit<1>>(4) isSeenPortEgress; //in order to identify first packet in the port(0 first Packet, 1 not)

    bit<48> _startTimePortEgress;
    register<bit<48>>(4) startTimePortEgress; //start time of port with index of port

    bit<32> link_load_egress;
    register<bit<32>>(4) linkLoadEgress; //current port based counter

    bit<32> prevPortBasedBytesEgress; //local help variable which is used with register "bytesReceivedPort"
    register<bit<32>>(4) bytesSentPort; //number of bytes received per port
    
    //for link level
    bit<1> _isSeenPort; //local help variable which is used with register "isSeenPort"
    register<bit<1>>(4) isSeenPort; //in order to identify first packet in the port(0 first Packet, 1 not)

    bit<32> prevPortBasedBytes; //local help variable which is used with register "bytesReceivedPort"
    register<bit<32>>(4) bytesReceivedPort; //number of bytes received per port

    bit<48> _startTimePort;
    register<bit<48>>(4) startTimePort; //start time of port with index of port

    bit<32> link_load;
    register<bit<32>>(4) linkLoad; //current port based counter

    //for flow level
    bit<1> _isSeen; //local help variable which is used with register "isSeen"
    register<bit<1>>(maxFlows) isSeen; //in order to identify first packet in the flow(0 first Packet, 1 not)

    bit<32> prevFlowBasedBytes; //local help variable which is used with register "bytesReceived"
    register<bit<32>>(maxFlows) bytesReceived; //number of bytes received per flow

    bit<48> _startTime; //local help variable which is used with register "startTime"
    register<bit<48>>(maxFlows) startTime; //start time of flows with index of flowId
  
    register<bit<32>>(maxFlows) dropRates; //drop rates per flow level which are calculated in controller
    register<bit<1>>(maxFlows) isHeavyHitter; //in order to undentify heavy hitters

    /*
    this function drops the packet and increases the counter for dropped packets per flow
    */
   action drop() {
        mark_to_drop(standard_metadata);
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

        //get flow id
        hash(flowId, HashAlgorithm.crc32, 32w0, {hdr.ipv4.srcAddr,hdr.ipv4.dstAddr, meta.l4_ports.src_port, meta.l4_ports.dst_port, hdr.ipv4.protocol}, maxFlows);

        /////////INGRESS////////////
        current_iPort = (bit<32>)standard_metadata.ingress_port;
    
        /*Is it a first packet of port, then note time of ingress. */  
        isSeenPort.read(_isSeenPort, current_iPort);
        if(_isSeenPort==0) {
            startTimePort.write(current_iPort, standard_metadata.ingress_global_timestamp);
            isSeenPort.write(current_iPort,1);
        }

        //link level window each 5 seconds
        startTimePort.read(_startTimePort, current_iPort);
        if(standard_metadata.ingress_global_timestamp - _startTimePort >= link_level_window) {
            //save bytes received from particular port each 5 seconds
            linkLoad.read(link_load,current_iPort);//read current bytes to link load
            bytesReceivedPort.write(current_iPort, link_load); //save link load to bytesReceivedPort with indexof ingress port
        
            //reset timer->current time is start time
            startTimePort.write(current_iPort, standard_metadata.ingress_global_timestamp);
            //reset counter
            linkLoad.write(current_iPort, 0);
        }
        
        //increase bytes received  by packet length port based
        linkLoad.read(link_load,(bit<32>)standard_metadata.ingress_port); //read current bytes
        linkLoad.write((bit<32>)standard_metadata.ingress_port, link_load + standard_metadata.packet_length); //increase byte counter by a package

        ////////INGRESS////////////


        /////////EGRESS////////////
        current_ePort = (bit<32>)standard_metadata.egress_spec;  // ?? egress_spec is correctly used?

        /*Is it a first packet of port, then note time of egress. */  
        isSeenPortEgress.read(_isSeenPortEgress, current_ePort);
        if (_isSeenPortEgress == 0) {
            startTimePortEgress.write(current_ePort, standard_metadata.egress_global_timestamp); // ?? egress_global_timestamp correct?
            isSeenPortEgress.write(current_ePort,1);
        }

        //link level window each 5 seconds
        startTimePortEgress.read(_startTimePortEgress, current_ePort);
        if (standard_metadata.egress_global_timestamp - _startTimePortEgress >= link_level_window) {
            //save bytes received from particular port each 5 seconds
            linkLoadEgress.read(link_load_egress, current_ePort);//read current bytes to link load
            bytesSentPort.write(current_ePort, link_load_egress); //save link load to bytesReceivedPort with indexof egress port
        
            //reset timer->current time is start time
            startTimePortEgress.write(current_ePort, standard_metadata.egress_global_timestamp);
            //reset counter
            linkLoadEgress.write(current_ePort, 0);
        }
       
        //increase bytes received  by packet length port based
        linkLoadEgress.read(link_load_egress,(bit<32>)standard_metadata.egress_port); //read current bytes
        linkLoadEgress.write((bit<32>)standard_metadata.egress_port, link_load_egress + standard_metadata.packet_length); //increase byte counter by a package
        
        /////////EGRESS END//////////// 


        /////////FLOW LEVEL WINDOW MANAGEMENT START////////////

        /*Is it a first packet of flow, then note time of ingress. */ 
        isSeen.read(_isSeen, flowId);
        if (_isSeen == 0) {
            startTime.write(flowId, standard_metadata.ingress_global_timestamp);
            isSeen.write(flowId,1);
        }    
        
        // flow level window each 15 seconds
        startTime.read(_startTime, flowId);
        if(standard_metadata.ingress_global_timestamp - _startTime >= flow_level_window) {
                
                //read previous port based by counter
                bytesReceivedPort.read(prevPortBasedBytes, current_iPort); //read ingress port based bytes to local var
                bytesSentPort.read(prevPortBasedBytesEgress, current_ePort); //read egress port based bytes to local var

                
                //if prev ingress or egress port based bytes are above 80% than limit 
                if((5 * prevPortBasedBytes > 4 * portBasedByteLimit) || (5 * prevPortBasedBytesEgress> 4 * portBasedByteLimit) ){ 

                        //get flow byte counter
                        bytesReceived.read(prevFlowBasedBytes, flowId);

                        //if this flow is above 50% of prev ingress link load 
                        if(2 * prevFlowBasedBytes > prevPortBasedBytes){ 
                            //clone
                            meta.flowid = flowId;
                            meta.prevFlowBasedBytesExceeded = prevFlowBasedBytes;
                            meta.prevPortBasedBytesExceeded = prevPortBasedBytes;
                            clone3(CloneType.I2E, MIRROR_SESSION_ID, meta); 
                            
                        }

                        //if this flow is above 50% of prev egress link load 
                        if(2 * prevFlowBasedBytes > prevPortBasedBytesEgress){ 
                            //clone
                            meta.flowid = flowId;
                            meta.prevFlowBasedBytesExceeded = prevFlowBasedBytes;
                            meta.prevPortBasedBytesExceeded = prevPortBasedBytesEgress;
                            clone3(CloneType.I2E, MIRROR_SESSION_ID, meta); 
                        }

                } 
                
                //reset flow level window
                startTime.write(flowId, standard_metadata.ingress_global_timestamp);
                //reset flow level counter
                bytesReceived.write(flowId, 0);
            }

            //increase bytes received  by packet length per flow
            bytesReceived.read(prevFlowBasedBytes,flowId);
            bytesReceived.write(flowId,prevFlowBasedBytes+standard_metadata.packet_length);
            
            /////////FLOW LEVEL WINDOW MANAGEMENT END////////////   

            //throttle to given drop drate probabilisticly if this flow is heavy hitter
            bit<1> isHH = 0;
            isHeavyHitter.read(isHH, flowId);        
            if(isHH == 1){
                //applying probabilistic drop rate if there is
                bit<32> probability;
                random<bit<32>>(probability, 32w0, 32w100);    // [0,...,100]
                bit<32> dropRate;
                dropRates.read(dropRate, flowId);
                log_msg("Heavy hitter flow {} is being dropped by {}", {flowId, dropRate});
                if (probability <= dropRate) {
                    drop();
                    log_msg("drop");
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
    apply {
          // if packet was cloned instance_type =1
        if (standard_metadata.instance_type == 1){
            // populate cpu header
            hdr.cpu.setValid();
            hdr.cpu.flowid = meta.flowid;
            hdr.cpu.prevFlowBasedBytesExceeded = meta.prevFlowBasedBytesExceeded;
            hdr.cpu.prevPortBasedBytesExceeded = meta.prevPortBasedBytesExceeded;
            
            // Disable other headers
            hdr.ethernet.setInvalid();
            hdr.ipv4.setInvalid();
        }

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
        packet.emit(hdr.cpu);
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
# SIMPLE TROTTLE

simple_throttle is a Verca project, that implements bandwidth throttle as a Intrusion Reaction to DDOS Attack using data plane programming. 

## Topology

We will use the following topology for this project: <br/> 
<br/>
![pod-topo](./pod-topo/simpleTopo.png)

## Usage
1. In your shell, run:
   ```bash
   make run
   ```
   This will:
   * compile `simple_throttle.p4`, and
   * start the pod-topo in Mininet and configure a switch with
   the appropriate P4 program + table entries, and
   * configure all hosts with the commands listed in
   [pod-topo/topology.json](./pod-topo/topology.json)

2. You should now see a Mininet command prompt. Try to run some iperf
   TCP flows between the hosts. 
   ```bash
   mininet> iperf h1 h2
   ```

3. Type `exit` to leave the Mininet command line.
   Then, to stop mininet:
   ```bash
   make stop
   ```
   And to delete all pcaps, build files, and logs:
   ```bash
   make clean
   ```

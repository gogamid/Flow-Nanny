
Throttling happening on sw1-h1
Run `sudo p4run` on one terminal
`sudo python controller.py` in another terminal

first terminal will open mininet
run `xterm h1 h1 h2 h3`

X Window will open four windows 
on h1 run `iperf3 -s -p 5678`
on another h1 run `iperf3 -s -p 5679`

h2 and h3 will send packets
on h2 run  `iperf3 -c 10.0.1.1 -t 200 -p 5678  -u`
on h3 run  `iperf3 -c 10.0.1.1 -t 200 -p 5679  -u`

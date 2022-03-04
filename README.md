# Flow Nanny

Data Plane: [P4 Code](src/basic.p4)
- run data plane code: `sudo p4run `

Control Plane: [Python Code](src/controller.py)
- run control plane main logic: `sudo python controller.py run `
- change drop rate: `sudo python controller.py set [flowid] [droprate]`


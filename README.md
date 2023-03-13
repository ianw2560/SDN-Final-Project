# SDN Final Project

## Usage

Create Mininet topology
```
sudo mn --topo mytopo --custom syn_flood_network_topo.py --controller=remote,ip=127.0.0.1,port=6653 --switch ovs,protocols=OpenFlow13 --link tc
```

Start floodlight
```
java -jar target/floodlight.jar
```
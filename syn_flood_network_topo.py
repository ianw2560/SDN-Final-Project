from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.topo import Topo

class MyTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add switches
        switches = {}
        for i in range(0, 11):
            switch = self.addSwitch('s{}'.format(i+1), cls=OVSSwitch)
            switches[i] = switch

        # Add TCP server connected to S8
        server = self.addHost('tcp_server')
        self.addLink(server, switches[7])

        # Add 30 hosts connected to S1-S4
        for i in range(1, 5):
            for j in range(1, 31):
                host = self.addHost('h{}_{}'.format(i, j))
                self.addLink(host, switches[i], bw=100)

        # Add links between switches
        for i in range(0, 4):
            self.addLink(switches[i], switches[i+8], bw=1000)
            
        # Add links between switches
        for i in range(5, 10):
            self.addLink(switches[i], switches[i+1], bw=1000)
        self.addLink(switches[10], switches[5], bw=1000)
        
        # Add remaining switch connections
        self.addLink(switches[7], switches[4], bw=1000)
        self.addLink(switches[8], switches[5], bw=1000)
        
        


topos = { 'mytopo': ( lambda: MyTopo() ) }

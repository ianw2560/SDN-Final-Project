from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo(Topo):

    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add switches
        switches = {}
        for i in range(1, 11 + 1):
            switch = self.addSwitch('s{}'.format(i), cls=OVSSwitch)
            switches[i-1] = switch

        # Add TCP server connected to S8
        server = self.addHost('tcp_server')
        self.addLink(server, switches[7])

        # Add 30 hosts connected to S1-S3
        for i in range(1, 3 +1):
            for j in range(1, 30 + 1):
                host = self.addHost('h{}_{}'.format(i, j))
                self.addLink(host, switches[i-1], bw=100)

        # Add 32 hosts connected to S4
        for i in range(1, 32 + 1):
            host = self.addHost('h{}_{}'.format(4, i))
            self.addLink(host, switches[4-1], bw=100)

        # Add links between switches S1-S9 S2-S10 S3-S11 S4-S5
        for i in range(1, 3+1):
            self.addLink(switches[i-1], switches[i+7-1], bw=1000)
        self.addLink(switches[4-1], switches[5-1], bw=1000)
            
        # Add links between switches
        for i in range(5, 10+1):
            self.addLink(switches[i-1], switches[i], bw=1000)
        self.addLink(switches[11-1], switches[5-1], bw=1000)
        
        # Add remaining switch connections
        self.addLink(switches[8-1], switches[5-1], bw=1000)
        self.addLink(switches[9-1], switches[6-1], bw=1000)

topos = { 'mytopo': ( lambda: MyTopo() ) }

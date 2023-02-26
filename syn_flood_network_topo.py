from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.topo import Topo

class MyTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Add switches
        switches = {}
        for i in range(1, 12):
            switch = self.addSwitch('s{}'.format(i), cls=OVSSwitch)
            switches[i] = switch

        # Add TCP server connected to S1
        server = self.addHost('server')
        self.addLink(server, switches[1])

        # Add 30 hosts connected to S2-S5
        for i in range(2, 6):
            for j in range(1, 31):
                host = self.addHost('h{}{}'.format(i, j))
                self.addLink(host, switches[i])

        # Add links between switches
        for i in range(1, 11):
            for j in range(i + 1, 12):
                self.addLink(switches[i], switches[j], bw=1000)

if __name__ == '__main__':
    topo = MyTopo()
    net = Mininet(topo=topo, controller=Controller)
    net.start()
    CLI(net)
    net.stop()

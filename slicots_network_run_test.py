from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.topo import SingleSwitchTopo
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.util import dumpNodeConnections, pmonitor
from mininet.log import setLogLevel, info

from functools import partial
import time
from signal import SIGINT


class MyTopo(Topo):

    def build(self):

        # Add switches
        switches = {}
        for i in range(1, 11 + 1):
            switch = self.addSwitch('s{}'.format(i))
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

def simpleTest(num_attackers=5, seconds=10):
    "Create and test a simple network"
    #topo = MyTopo()
    topo = SingleSwitchTopo( 10 )

    ovs13 = partial(OVSSwitch, protocols='OpenFlow13')

    net = Mininet(topo=topo, 
                  controller=None,
                  link=TCLink,
                  switch=ovs13,
                  autoSetMacs=True,
                  waitConnected=True)
    net.addController('c0', controller=RemoteController, ip='192.168.56.106', port=6653)


    net.start()

    hosts = net.hosts
    # benign1 = net.get('h4_31')
    # benign2 = net.get('h4_32')

    # info('benign1 IP:', benign1.IP(),'\n')
    # info('benign2 IP:', benign2.IP(),'\n')

    info( "Starting test...\n" )

    server = hosts[-1]

    attacker_hosts = hosts[:5]

    info("Starting HTTP server on tcp_server host...\n")
    print( server.cmd('python3 -m http.server 80 &') )
    

    info("The IP of the TCP server is:", server.IP(),"\n")

    print( server.cmd('tcpdump -i h10-eth0 -w syn_flood_capture'+str(seconds)+'sec.pcap &') )
    #print( server.cmd('tcpdump -i tcp_server-eth0 -w syn_flood_capture'+str(seconds)+'sec.pcap &') )

    # Let tcpdump initalize
    time.sleep(1)
    
    info( "Monitoring output for", seconds, "seconds\n" )
    endTime = time.time() + seconds
    # while time.time() < endTime:
    #     benign1.cmd('wget -O -', server.IP())
    #     benign2.cmd('wget -O -', server.IP())
    #     time.sleep(4)
    while time.time() < endTime:
        for h in attacker_hosts:
            h.cmd('hping3 -c 1 -S -a', h.IP(), server.IP())

        net.get('h7').cmd('wget -O -', server.IP())
        net.get('h8').cmd('wget -O -', server.IP())
        time.sleep(4)

    print( server.cmd('kill %tcpdump') )

    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest(num_attackers=5, seconds=20)
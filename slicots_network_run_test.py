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

def scenarioS1(num_attackers, duration):

    """
    In Scenario S1, the number of attackers varies from 20 to 120.
    Each attacker sends three SYN packets every second.
    Two benign hosts send HTTP GET requests every 4 seconds.
    """

    # Build Mininet network
    topo = MyTopo()

    # Specify switch configuration
    ovs13 = partial(OVSSwitch, protocols='OpenFlow13')

    # Mininet constructor
    net = Mininet(topo=topo, 
                  controller=None,
                  link=TCLink,
                  switch=ovs13,
                  autoSetMacs=True,
                  waitConnected=True)

    # Add controller
    net.addController('c0', controller=RemoteController, ip='192.168.56.106', port=6653)

    net.start()

    hosts = net.hosts

    # Set up the two constant benign hosts
    benign1 = net.get('h4_31')
    benign2 = net.get('h4_32')

    info('benign1 IP:', benign1.IP(),'\n')
    info('benign2 IP:', benign2.IP(),'\n')

    # Make the server the last host
    server = hosts[-1]

    # Set hosts to be attackers
    attackers = hosts[:num_attackers]

    # Start HTTP server on tcp_server host
    info("Starting HTTP server on tcp_server host...\n")
    print( server.cmd('python3 -m http.server 80 &') )
    

    info("The IP of the TCP server is:", server.IP(),"\n")

    info( "Starting test...\n" )

    # Start tcpdump to listen on tcp_server-eth0 interface
    print( server.cmd('tcpdump -i tcp_server-eth0 -w captures/scenario1_'+str(num_attackers)+'attackers_'+str(duration)+'sec.pcap &') )

    # Let tcpdump initalize
    time.sleep(1)
    
    info( "Monitoring output for", duration, "seconds\n" )
    endTime = time.time() + duration
    num_get_reqs = 0

    # Send SYN packets and HTTP requests
    while time.time() < endTime:
        
        for h in attackers:
            h.cmd('hping3 -c 3 -S  --rand-source', server.IP(), '&')

        time.sleep(1)

        for h in attackers:
             h.cmd('hping3 -c 3 -S  --rand-source', server.IP(), '&')

        time.sleep(1)

        for h in attackers:
             h.cmd('hping3 -c 3 -S  --rand-source', server.IP(), '&')

        time.sleep(1)

        for h in attackers:
             h.cmd('hping3 -c 3 -S  --rand-source', server.IP(), '&')

        info("Sending GET requests...\n")
        num_get_reqs = num_get_reqs + 1
        benign1.cmd('wget -O -', server.IP())
        benign2.cmd('wget -O -', server.IP())
        time.sleep(1)

    print( server.cmd('kill %tcpdump') )

    info("Total number of GET requests:", num_get_reqs,"\n")

    net.stop()

if __name__ == '__main__':

    # Tell mininet to print useful information
    setLogLevel('info')

    test_duration = 60

    scenarioS1(num_attackers=0, duration=test_duration)
    scenarioS1(num_attackers=20, duration=test_duration)
    scenarioS1(num_attackers=40, duration=test_duration)
    scenarioS1(num_attackers=60, duration=test_duration)
    scenarioS1(num_attackers=80, duration=test_duration)
    scenarioS1(num_attackers=100, duration=test_duration)
    scenarioS1(num_attackers=120, duration=test_duration)
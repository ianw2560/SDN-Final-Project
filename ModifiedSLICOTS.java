package net.floodlightcontroller.modifiedslicots;

import java.util.Collection;
import java.util.Map;
 
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
 
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ModifiedSLICOTS implements IOFMessageListener, IFloodlightModule {
	
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	ArrayList<Connection> pendingList;
	protected int K;
	protected int hard_timeout;
	
    @Override
    public String getName() {
    	return ModifiedSLICOTS.class.getSimpleName();
    }

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	            new ArrayList<Class<? extends IFloodlightService>>();
	        l.add(IFloodlightProviderService.class);
	        return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    logger = LoggerFactory.getLogger(ModifiedSLICOTS.class);
	    pendingList = new ArrayList<Connection>();
	    K = 50;
	    hard_timeout = 3;
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
	    switch (msg.getType()) {
	    case PACKET_IN:
	    	
	    	//PacketHandler ph = new PacketHandler(sw, msg, cntx);
	    	
	        /* Retrieve the deserialized packet in message */
	        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	        
	        // We have a new IP packet
	        if (eth.getEtherType() == EthType.IPv4) {
	        	
	            /* We got an IPv4 packet; get the payload from Ethernet */
	            IPv4 ipv4 = (IPv4) eth.getPayload();
	             
	            // Check if the IP protocol is TCP
	            if (ipv4.getProtocol() == IpProtocol.TCP) {
	                
	            	/* We got a TCP packet; get the payload from IPv4 */
	                TCP tcp = (TCP) ipv4.getPayload();
	            	
	                // Get TCP src IP, dst IP, src MAC, and dst MAC
	                TransportPort srcPort = tcp.getSourcePort();
	                TransportPort dstPort = tcp.getDestinationPort();
	                MacAddress srcMac = eth.getSourceMACAddress();
	                MacAddress dstMac = eth.getDestinationMACAddress();
	                
	                short flags = tcp.getFlags();
	                
	                int C;
	                
	                // Is SYN?
	                if (tcp.getFlags() == 2) {
	                	
	                	C = this.getNumIllegitimateRequests(pendingList, srcMac);
	                	
	                	if (C > K) {
	                		// Install forwarding rule to block the requested host
	                	} else {
		                	Connection record = new Connection(srcPort, dstPort, srcMac, dstMac, "SYN");
		                	pendingList.add(record);
		                	
		                	// Install temporary forwarding rule between client and server
	                	}
	                	
	                // Is RST?
	                } else if (tcp.getFlags() == 4) {
	                	
	                	C = this.getNumIllegitimateRequests(pendingList, srcMac);
	                	
	                	if (C > K) {
	                		// Install forwarding rule to block the requested host
	                	} else {
	                		// Find related record in pendingList and update status to RST
		                	this.setPendingListStatus(srcPort, dstPort, srcMac, dstMac, "RST");
	                	}
	                	
	                // Is SYN-ACK?
	                } else if (tcp.getFlags() == 18) {
	                	
                		// Find related record in pendingList and update status to SYN-ACK
	                	this.setPendingListStatus(srcPort, dstPort, srcMac, dstMac, "SYN-ACK");
	                	
	                	// Install temporary forwarding rule between client and server
	                
	                // Is ACK?
	                } else if (tcp.getFlags() == 16) {
	                	
	                	this.removePendingListRecord(srcPort, dstPort, srcMac, dstMac);
	                	
	                	// Install permanent forwarding rule between client and server
	                }
	            }
	        }
	  
	        
//	        // Create a new packet-out message to send the packet back out
//	        OFPacketOut po = sw.getOFFactory().buildPacketOut()
//	            .setData(packetData)
//	            .setActions(Collections.singletonList(sw.getOFFactory().actions().output(outPort, 0xffFFffFF)))
//	            .setInPort(inPort)
//	            .build();
//
//	        // Send the packet-out message to the switch
//	        sw.write(po);
//	        
	        
	        
	        break;
	    default:
	        break;
	    }
	    return Command.CONTINUE;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}
	
	private int getNumIllegitimateRequests(ArrayList<Connection> pendingList, MacAddress srcMac) {
		int numIllegitRequests = 0;
		
		// Loop through all records in the pending_list
		for (Connection record : pendingList) {
			
			// Check if the record is an illegit requests
			if (record.getStatus() == "SYN" || record.getStatus() == "SYN-ACK" || record.getStatus() == "RST") {
				
				// Check if it comes from the specified client
				if (record.getSrcMac() == srcMac) {
					numIllegitRequests++;
				}
			}
		}
		
		return numIllegitRequests;
	}
	
	private void setPendingListStatus(TransportPort srcPort, TransportPort dstPort, MacAddress srcMac, MacAddress dstMac, String status) {
		// Loop through all records in the pending_list
		for (Connection record : pendingList) {
			
			// Get the matching record
			if (record.getSrcPort() == srcPort &&
				record.getDstPort() == dstPort && 
				record.getSrcMac() == srcMac &&
				record.getDstMac() == dstMac) {
				
				// Change the matching record's status
				record.setStatus(status);
			}
		}
	}
	
	private void removePendingListRecord(TransportPort srcPort, TransportPort dstPort, MacAddress srcMac, MacAddress dstMac) {
		// Loop through all records in the pending_list
		for (Connection record : pendingList) {
			
			// Get the matching record
			if (record.getSrcPort() == srcPort &&
				record.getDstPort() == dstPort && 
				record.getSrcMac() == srcMac &&
				record.getDstMac() == dstMac) {
				
				// Remove the specified record
				pendingList.remove(record);
			}
		}
	}

}

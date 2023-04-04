package net.floodlightcontroller.modifiedslicots;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
 
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.MatchField;
 
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
	private List<Connection> pendingList;
	protected int K;
	protected int hard_timeout;
	private HashMap<MacAddress, Integer> C_map;
	
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
	    pendingList = Collections.synchronizedList(new ArrayList<Connection>());
	    C_map = new HashMap<MacAddress, Integer>();
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
	                IPv4Address srcIp = ipv4.getSourceAddress();
	                IPv4Address dstIp = ipv4.getDestinationAddress();
	                MacAddress srcMac = eth.getSourceMACAddress();
	                MacAddress dstMac = eth.getDestinationMACAddress();
	                
	                short flags = tcp.getFlags();
	                
	                if (C_map.containsKey(srcMac)) {
	                	C_map.put(srcMac, 0);
	                }
	                
	                
	                DatapathId dpid = sw.getId();
	                int C;
	                
	                // Is SYN?
	                if (tcp.getFlags() == 2) {
	            
	                	C_map.put(srcMac, this.getNumIllegitimateRequests(pendingList, srcMac));
	                	C = C_map.get(srcMac);

	                	
	                	logger.info("[Switch= {}][SrcMAC = {}] SYN", dpid.toString(), srcMac.toString());
	                	logger.info("C = {}", C);
	                	
	                	if (C > K) {
	                		// Install forwarding rule to block the requested host
	                	} else {
		                	Connection record = new Connection(srcIp, dstIp, srcMac, dstMac, "SYN");
		                	
		                	logger.info("Adding pending record on switch {}", srcMac.toString());
		                	pendingList.add(record);
		                	
		                	// Install temporary forwarding rule between client and server
	                	}
	                	
	                // Is RST?
	                } else if (tcp.getFlags() == 4) {
	                	
	                	C_map.put(srcMac, this.getNumIllegitimateRequests(pendingList, srcMac));
	                	C = C_map.get(srcMac);
	                	
	                	logger.info("[Switch= {}][SrcMAC = {}] RST", dpid.toString(), srcMac.toString());
	                	logger.info("C = {}", C);
	                	
	                	if (C > K) {
	                		// Install forwarding rule to block the requested host
	                	} else {
	                		// Find related record in pendingList and update status to RST
		                	this.setPendingListStatus(srcIp, dstIp, srcMac, dstMac, "RST");
	                	}
	                	
	                // Is SYN-ACK?
	                } else if (tcp.getFlags() == 18) {
	                	
	                	logger.info("[Switch= {}][SrcMAC = {}] SYN-ACK", dpid.toString(), srcMac.toString());
	                	
                		// Find related record in pendingList and update status to SYN-ACK
	                	this.setPendingListStatus(srcIp, dstIp, srcMac, dstMac, "SYN-ACK");
	                	
	                	// Install temporary forwarding rule between client and server
	                
	                // Is ACK?
	                } else if (tcp.getFlags() == 16) {
	                	
	                	logger.info("[Switch= {}][SrcMAC = {}] ACK", dpid.toString(), srcMac.toString());
	                	
	                	this.removePendingListRecord(srcIp, dstIp, srcMac, dstMac);
	                	
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
	
	private int getNumIllegitimateRequests(List<Connection> pendingList, MacAddress srcMac) {
		int numIllegitRequests = 0;
		
		// Loop through all records in the pending_list
		for (Connection record : pendingList) {
			
			// Check if the record is an illegit requests
			if (record.getStatus() == "SYN" || record.getStatus() == "SYN-ACK" || record.getStatus() == "RST") {
		
				
				// Check if it comes from the specified client
				//logger.info("record.getSrcMac() = {}  srcMac = {}", record.getSrcMac().toString(), srcMac.toString());
				if (record.getSrcMac().equals(srcMac)) {
					numIllegitRequests++;
				}
			}
		}
		
		return numIllegitRequests;
	}
	
	private void setPendingListStatus(IPv4Address srcIp, IPv4Address dstIp, MacAddress srcMac, MacAddress dstMac, String status) {
		// Loop through all records in the pending_list
		for (Connection record : pendingList) {
			
			// Get the matching record
			if (record.getSrcIp() == srcIp &&
				record.getDstIp() == dstIp && 
				record.getSrcMac() == srcMac &&
				record.getDstMac() == dstMac) {
				
				// Change the matching record's status
				synchronized(pendingList) {
					record.setStatus(status);
				}
			}
		}
	}
	
	private void removePendingListRecord(IPv4Address srcIp, IPv4Address dstIp, MacAddress srcMac, MacAddress dstMac) {
		// Loop through all records in the pending_list
		for (Connection record : pendingList) {
			
			// Get the matching record
			if (record.getSrcIp() == srcIp &&
				record.getDstIp() == dstIp && 
				record.getSrcMac() == srcMac &&
				record.getDstMac() == dstMac) {
				
				// Remove the specified record
				synchronized(pendingList) {
					pendingList.remove(record);
				}
			}
		}
	}

//	public void installForwardingRules(DatapathId srcDpid, DatapathId dstDpid, OFPort inPort, OFPort outPort, int hardTimeout) {
//	    IOFSwitch sw;
//		// Create OFFactory object for creating flow rule
//	    OFFactory factory = sw.getOFFactory();
//
//	    // Add flow rule on first switch connected to source host to forward packets to the controller
//	    OFMatch match = factory.buildMatch().setExact(MatchField.IN_PORT, inPort).build();
//	    OFInstructionGotoTable goToTable = factory.instructions().gotoTable(TableId.of(1));
//	    OFInstructionApplyActions applyActions = factory.instructions().applyActions(Collections.singletonList((OFAction) factory.actions().output(OFPort.CONTROLLER, Integer.MAX_VALUE)));
//	    OFFlowAdd flowAdd = factory.buildFlowAdd().setMatch(match).setHardTimeout(hardTimeout).setInstructions(Arrays.asList(goToTable, applyActions)).build();
//	    IOFSwitch firstSwitch = switchService.getSwitch(srcDpid);
//	    firstSwitch.write(flowAdd);
//
//	    // Add flow rule on switches along the path from source host to destination host
//	    DatapathId currDpid = srcDpid;
//	    while (!currDpid.equals(dstDpid)) {
//	        // Get next hop switch and out port
//	        Link link = linkService.getEgressLinks(currDpid).get(0);
//	        currDpid = link.getDst().getDpid();
//	        OFPort outPort = link.getDstPort();
//
//	        // Build match for current switch and create flow rule
//	        OFMatch match = factory.buildMatch().setExact(MatchField.IN_PORT, inPort).setExact(MatchField.ETH_DST, dstMac).build();
//	        OFInstructionApplyActions applyActions = factory.instructions().applyActions(Collections.singletonList((OFAction) factory.actions().output(outPort, Integer.MAX_VALUE)));
//	        OFFlowAdd flowAdd = factory.buildFlowAdd().setMatch(match).setHardTimeout(hardTimeout).setInstructions(Collections.singletonList((OFInstruction) applyActions)).build();
//	        IOFSwitch currSwitch = switchService.getSwitch(currDpid);
//	        currSwitch.write(flowAdd);
//
//	        // Update in port for next hop
//	        inPort = outPort;
//	    }
//	}


}

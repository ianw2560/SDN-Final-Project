package net.floodlightcontroller.modifiedslicots;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
 
import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.match.MatchFields;
 
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.internal.OFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ModifiedSLICOTS implements IOFMessageListener, IFloodlightModule {
	
	private static IFloodlightProviderService floodlightProvider;
	private static ITopologyService floodlightTopology;
	
	protected static Logger logger;
	private List<Connection> pendingList;
	protected int K;
	protected int hard_timeout;
	private ConcurrentHashMap<MacAddress, Integer> C_map;
	
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
	    floodlightTopology = context.getServiceImpl(ITopologyService.class);
	    
	    logger = LoggerFactory.getLogger(ModifiedSLICOTS.class);
	    pendingList = Collections.synchronizedList(new ArrayList<Connection>());
	    C_map = new ConcurrentHashMap<MacAddress, Integer>();
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
	                
	                // Get src dpid
	                DatapathId srcDpid = sw.getId();

	                short flags = tcp.getFlags();
	                int C;
	                
	                if (C_map.containsKey(srcMac)) {
	                	C_map.put(srcMac, 0);
	                }
	                
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
		                	this.installTemporaryForwardingRules(srcDpid, dstDpid, sw);
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
	                	this.installTemporaryForwardingRules(srcDpid, dstDpid, sw);
	                
	                // Is ACK?
	                } else if (tcp.getFlags() == 16) {
	                	
	                	//logger.info("[Switch= {}][SrcMAC = {}] ACK", dpid.toString(), srcMac.toString());
	                	int c = this.getNumIllegitimateRequests(pendingList, srcMac);
	                	logger.info("[SrcMAC = {}] Before ACK: {}", srcMac.toString(), c);
	                	this.removePendingListRecord(srcIp, dstIp, srcMac, dstMac);
	                	
	                	c = this.getNumIllegitimateRequests(pendingList, srcMac);
	                	logger.info("[SrcMAC = {}] After ACK: {}", srcMac.toString(), c);
	                	
	                	// Install permanent forwarding rule between client and server
						this.installPermanentForwardingRules(srcDpid, dstDpid, IOFSwitch sw);
	                }
	            }
	        }
	        
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
	
	private void installTemporaryForwardingRules(DatapathId srcDpid, DatapathId dstDpid, IOFSwitch sw) {

	}

	private void installPermanentForwardingRules(DatapathId srcDpid, DatapathId dstDpid, IOFSwitch sw) {
		
	}

	private int getNumIllegitimateRequests(List<Connection> pendingList, MacAddress srcMac) {
		int numIllegitRequests = 0;
		
		// Loop through all records in the pending_list
		for (Connection record : pendingList) {
			
			String status = record.getStatus();
			
			// Check if the record is an illegit requests
			if (status.equals("SYN") || status.equals("SYN-ACK") || status.equals("RST")) {
		
				// Check if it comes from the specified client
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
			if (record.getSrcMac().equals(srcMac)) {
				
				// Change the matching record's status
				synchronized(pendingList) {
					record.setStatus(status);
				}
			}
		}
	}
	
	private void removePendingListRecord(IPv4Address srcIp, IPv4Address dstIp, MacAddress srcMac, MacAddress dstMac) {

	    synchronized (pendingList) {
	        Iterator<Connection> iter = pendingList.iterator();
	        while (iter.hasNext()) {
	            Connection record = iter.next();
	            if (record.getSrcMac().equals(srcMac)) {
	                iter.remove();
	                break;
	            }
	        }
	    }
		
	}

}

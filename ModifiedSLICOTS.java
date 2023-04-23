package net.floodlightcontroller.modifiedslicots;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
 
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U16;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
 
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ModifiedSLICOTS implements IOFMessageListener, IFloodlightModule {
	
	private static IFloodlightProviderService floodlightProvider;
	private static IRoutingService routingService;
	private static IOFSwitchService switchService;
	private static IDeviceService deviceService;
	
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
	    routingService = context.getServiceImpl(IRoutingService.class);
	    switchService = context.getServiceImpl(IOFSwitchService.class);
	    deviceService = context.getServiceImpl(IDeviceService.class);

	    logger = LoggerFactory.getLogger(ModifiedSLICOTS.class);
	    pendingList = Collections.synchronizedList(new ArrayList<Connection>());
	    C_map = new ConcurrentHashMap<MacAddress, Integer>();
	    K = 50;
	    hard_timeout = 3;
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
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
	                
	                // Get src and dst DPIDs
	                DatapathId srcDpid = sw.getId();
	                DatapathId dpid = srcDpid;
	                DatapathId dstDpid = this.getDpidFromMac(dstMac);

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
	                		this.dropPackets(srcMac);
	                		
	                	} else {
		                	Connection record = new Connection(srcIp, dstIp, srcMac, dstMac, "SYN");
		                	
		                	logger.info("Adding pending record for host {}", srcMac.toString());
		                	pendingList.add(record);
		                	
		                	// Install temporary forwarding rule between client and server
		                	this.installTemporaryForwardingRules(srcDpid, dstDpid, srcMac, dstMac, sw, hard_timeout);
	                	}
	                	
	                // Is RST?
	                } else if (tcp.getFlags() == 4) {
	                	
	                	C_map.put(srcMac, this.getNumIllegitimateRequests(pendingList, srcMac));
	                	C = C_map.get(srcMac);
	                	
	                	logger.info("[Switch= {}][SrcMAC = {}] RST", dpid.toString(), srcMac.toString());
	                	logger.info("C = {}", C);
	                	
	                	if (C > K) {
	                		// Install forwarding rule to block the requested host
	                		logger.info("C>K!!!");
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
	                	this.installTemporaryForwardingRules(srcDpid, dstDpid, srcMac, dstMac, sw, hard_timeout);
	                
	                // Is ACK?
	                } else if (tcp.getFlags() == 16) {
	                	
	                	//logger.info("[Switch= {}][SrcMAC = {}] ACK", dpid.toString(), srcMac.toString());
	                	int c = this.getNumIllegitimateRequests(pendingList, srcMac);
	                	logger.info("[SrcMAC = {}] Before ACK: {}", srcMac.toString(), c);
	                	this.removePendingListRecord(srcIp, dstIp, srcMac, dstMac);
	                	
	                	c = this.getNumIllegitimateRequests(pendingList, srcMac);
	                	logger.info("[SrcMAC = {}] After ACK: {}", srcMac.toString(), c);
	                	
	                	// Install permanent forwarding rule between client and server
	                	this.installTemporaryForwardingRules(srcDpid, dstDpid, srcMac, dstMac, sw, 0);
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
	
	private DatapathId getDpidFromMac(MacAddress macAddr) {
        Iterator<? extends IDevice> iter = deviceService.queryDevices(macAddr, null, IPv4Address.NONE, IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);

        if (iter.hasNext()) {
            IDevice device = iter.next();
            
            SwitchPort[] attachmentPoints = device.getAttachmentPoints();
            SwitchPort attachmentPoint = attachmentPoints[0];
            DatapathId switchId = attachmentPoint.getSwitchDPID();
            
            logger.info("Destination switch dpid: {}", switchId.toString());
            
            return switchId;
        } else {
        	return null;
        }
	}
	
	public void dropPackets(MacAddress macAddressToDrop) {

	    Map<DatapathId, IOFSwitch> allSwitches = switchService.getAllSwitchMap();
	    for (IOFSwitch sw : allSwitches.values()) {
	        OFFactory factory = sw.getOFFactory();
	        Match match = factory.buildMatch()
	                .setExact(MatchField.ETH_SRC, macAddressToDrop)
	                .build();

	        OFFlowMod.Builder flowModBuilder = factory.buildFlowAdd()
	                .setMatch(match)
	                .setPriority(32768)
	                .setBufferId(OFBufferId.NO_BUFFER)
	                .setTableId(TableId.ZERO);

	        sw.write(flowModBuilder.build());
	    }
	}
	
	private void installTemporaryForwardingRules(DatapathId srcDpid, DatapathId dstDpid, MacAddress srcMac, MacAddress dstMac, IOFSwitch sw, int hardTimeout) {
	    Route route = routingService.getRoute(srcDpid, dstDpid, U64.ZERO);
	    List<NodePortTuple> path = route.getPath();

	    for (int i = 0; i < path.size(); i += 2) {
	        installForwardingRule(path, i, srcMac, dstMac, hardTimeout);
	    }

	    Route reverseRoute = routingService.getRoute(dstDpid, srcDpid, U64.ZERO);
	    List<NodePortTuple> reversePath = reverseRoute.getPath();

	    for (int i = 0; i < reversePath.size(); i += 2) {
	        installForwardingRule(reversePath, i, dstMac, srcMac, hardTimeout);
	    }
	}

	private void installForwardingRule(List<NodePortTuple> path, int index, MacAddress srcMac, MacAddress dstMac, int hardTimeout) {
	    NodePortTuple npt = path.get(index);
	    if (npt == null) {
	        logger.info("NPT {} is NULL", index);
	        return;
	    }

	    IOFSwitch currentSwitch = switchService.getSwitch(npt.getNodeId());
	    OFFlowMod.Builder fmb = currentSwitch.getOFFactory().buildFlowAdd();

	    Match match = currentSwitch.getOFFactory().buildMatch()
	            .setExact(MatchField.ETH_TYPE, EthType.IPv4)
	            .setExact(MatchField.IP_PROTO, IpProtocol.TCP)
	            .setExact(MatchField.ETH_SRC, srcMac)
	            .setExact(MatchField.ETH_DST, dstMac)
	            .build();

	    List<OFAction> actions = new ArrayList<OFAction>();
	    actions.add(currentSwitch.getOFFactory().actions().buildOutput()
	            .setMaxLen(0xffFFffFF)
	            .setPort(npt.getPortId())
	            .build());

	    if (hardTimeout == 0) {
	        fmb.setMatch(match)
	                .setPriority(32769)
	                .setActions(actions);
	    } else {
	        fmb.setMatch(match)
	                .setPriority(32769)
	                .setActions(actions)
	                .setHardTimeout(hardTimeout);
	    }

	    currentSwitch.write(fmb.build());
	}


	private int getNumIllegitimateRequests(List<Connection> pendingList, MacAddress srcMac) {
		int numIllegitRequests = 0;
		
		// Loop through all records in the pending_list
		synchronized (pendingList) {
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
	            if (record.getSrcMac().equals(srcMac) && record.getSrcIp().equals(srcIp) && record.getDstIp().equals(dstIp) && record.getDstMac().equals(dstMac)) {
	                iter.remove();
	                break;
	            }
	        }
	    }
	}
}

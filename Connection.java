package net.floodlightcontroller.modifiedslicots;

import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TransportPort;

public class Connection {
    private TransportPort srcPort;
    private TransportPort dstPort;
    private MacAddress srcMac;
    private MacAddress dstMac;
    private String status;

    public Connection(TransportPort srcPort, TransportPort dstPort, MacAddress srcMac, MacAddress dstMac, String status) {
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.srcMac = srcMac;
        this.dstMac = dstMac;
        this.status = status;
    }
    
    public TransportPort getSrcPort() {
        return srcPort;
    }
    
    public TransportPort getDstPort() {
        return dstPort;
    }
    
    public MacAddress getSrcMac() {
        return srcMac;
    }
    
    public MacAddress getDstMac() {
        return dstMac;
    }
    
    public String getStatus() {
        return status;
    }
    
    public void setStatus(String status) {
        this.status = status;
    }
    
}

package com.tufin.lib.datatypes.accessrequest;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * Network representation
 *
 *
 * @author Tufin PS-Dev support@tufin.com
 */
@XmlType(name = "ip_network")
public class IPNetwork extends AccessRequestAbstract {
    @XmlElement(name = "network")
    public NetworkAbstract network;

    public void setNetwork(String ip, String mask) {
        RawNetworkSubnet net = new RawNetworkSubnet();
        net.setIP(ip);
        net.setMask(mask);
        this.network = net;
    }

    public String prettyPrint() {
        return network.prettyPrint();
    }
}

package com.tufin.lib.datatypes.accessrequest;

import javax.xml.bind.annotation.XmlType;


/**
 * Simple IP and Netmask representation
 *
 * @author Tufin PS-Dev support@tufin.com
 */
@XmlType(name = "raw_network_subnet")
public class RawNetworkSubnet extends NetworkAbstract {
    public String ip;
    public String mask;

    public void setIP(String ip) {
        this.ip = ip;
    }

    public void setMask(String mask) {
        this.mask = mask;
    }

    public String prettyPrint() {
        return ip + "/" + mask;
    }
}

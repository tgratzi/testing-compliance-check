package com.tufin.lib.dataTypes.accessrequest;

import javax.xml.bind.annotation.XmlElement;


/**
 * Access request representation
 *
 * Hold access request information and generate XML
 * The source, destination and service will get AccessRequest abstract class in order to able to represent the
 * XSI:type during the XML creation. This achieved by assign different data type during the initialization.
 *
 * @author Tufin PS-Dev support@tufin.com
 */
public class AccessRequest {
    @XmlElement(name = "use_topology")
    public String useTopology;

    @XmlElement(name = "access_request_order")
    public String order;

    @XmlElement(name = "access_request_source")
    private AccessRequestAbstract source;

    @XmlElement(name = "access_request_destination")
    private AccessRequestAbstract dest;

    @XmlElement(name = "access_request_service")
    private AccessRequestAbstract srv;

    @XmlElement(name = "action")
    private String action = "ACCEPT";

    public void setSource(String ip, String mask) {
        IPNetwork src = new IPNetwork();
        src.setNetwork(ip, mask);
        this.source = src;
    }

    public void setDestination(String ip, String mask) {
        IPNetwork dst = new IPNetwork();
        dst.setNetwork(ip, mask);
        this.dest = dst;
    }

    public void setService(String name, int protocol, int toPort, int fromPort) {
        ImplicitService srv = new ImplicitService();
        srv.setName(name);
        srv.setService(protocol, toPort, fromPort);
        this.srv = srv;
    }

    public String getSource() {
        return source.prettyPrint();
    }

    public String getDestination() {
        return dest.prettyPrint();
    }

    public String getService() {
        return srv.prettyPrint();
    }
}

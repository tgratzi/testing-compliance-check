package com.tufin.lib.dataTypes.securitygroup;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import static com.tufin.lib.dataTypes.generic.Attributes.*;


/**
 * SecurityGroup representation
 *
 * Hold rule information and can transform to JSON format.
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class SecurityGroup {
    @JsonProperty("IpProtocol")
    String protocol;

    @JsonProperty("FromPort")
    Integer fromPort;

    @JsonProperty("ToPort")
    Integer toPort;

    @JsonProperty(CIDR_IP)
    String cidrIP;

    @JsonIgnore
    String direction;

    public void setDirection(String direction) {
        this.direction = direction;
    }

    public String getDirection() {
        return this.direction.equalsIgnoreCase(INGRESS) ? INBOUND : OUTBOUND;
    }

    public String getCidrIP() {
        return cidrIP;
    }

    public Integer getFromPort() {
        return fromPort;
    }

    public Integer getToPort() {
        return toPort;
    }

    public String getProtocol() {
        return protocol;
    }
}

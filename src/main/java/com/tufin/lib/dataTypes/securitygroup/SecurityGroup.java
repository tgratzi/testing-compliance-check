package com.tufin.lib.dataTypes.securitygroup;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;


public class SecurityGroup {
    public static final String INGRESS = "SecurityGroupIngress";
    public static final String EGRESS = "SecurityGroupEgress";
    public static final String INBOUND = "Inbound";
    public static final String OUTBOUND = "Outbound";

    @JsonProperty("IpProtocol")
    String protocol;

    @JsonProperty("FromPort")
    Integer fromPort;

    @JsonProperty("ToPort")
    Integer toPort;

    @JsonProperty("CidrIp")
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

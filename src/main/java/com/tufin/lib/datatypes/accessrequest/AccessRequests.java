package com.tufin.lib.datatypes.accessrequest;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;


/**
 * Multi Access request representation
 *
 * Hold list of access request information and generate XML
 *
 * @author Tufin PS-Dev support@tufin.com
 */
@XmlRootElement(name = "access_requests")
@XmlAccessorType(XmlAccessType.FIELD)
public class AccessRequests {
    @XmlElement(name = "access_request")
    private List<AccessRequest> accessRequests = new ArrayList<>();

    public List<AccessRequest> getAccessRequests() {
        return accessRequests;
    }

    public void setAccessRequests(List<AccessRequest> accessRequests) {
        this.accessRequests = accessRequests;
    }
}

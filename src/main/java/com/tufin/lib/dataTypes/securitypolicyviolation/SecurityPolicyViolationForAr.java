package com.tufin.lib.dataTypes.securitypolicyviolation;

import com.tufin.lib.dataTypes.generic.Elements;
import org.json.simple.JSONObject;


/**
 * Security Policy Violations For single Access Request
 *
 * Parse the security policy violation response for access request based on the USP
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class SecurityPolicyViolationForAr {
    private int access_request_order;
    private Violation violations;

    public SecurityPolicyViolationForAr(JSONObject json) {
        this.access_request_order = Integer.parseInt(json.get(Elements.ACCESS_REQUEST_ORDER).toString());
        Object violations = json.get(Elements.VIOLATIONS);
        if (violations instanceof String) {
            this.violations = null;
        } else {
            this.violations = new Violation((JSONObject) json.get(Elements.VIOLATIONS));
        }
    }

    public Violation getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return  (violations != null);
    }
}

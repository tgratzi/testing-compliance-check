package com.tufin.lib.datatypes.securitypolicyviolation;

import com.tufin.lib.datatypes.generic.Elements;
import org.json.simple.JSONObject;

/**
 * Security Policy Violations For Multi Access Request
 *
 * Parse the security policy violation response for multiple access requests based on the USP
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class SecurityPolicyViolationsForMultiAr {
    private SecurityPolicyViolationForAr securityPolicyViolationsForAr;

    public SecurityPolicyViolationsForMultiAr(JSONObject json) {
        JSONObject topElement = (JSONObject) json.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR);
        JSONObject securityPolicyViolationsForArElement =  (JSONObject) topElement.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_AR);
        this.securityPolicyViolationsForAr = new SecurityPolicyViolationForAr(securityPolicyViolationsForArElement);
    }

    public SecurityPolicyViolationForAr getSecurityPolicyViolationsForAr() {
        return securityPolicyViolationsForAr;
    }
}

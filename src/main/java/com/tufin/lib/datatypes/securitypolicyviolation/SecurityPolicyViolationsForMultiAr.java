package com.tufin.lib.datatypes.securitypolicyviolation;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tufin.lib.datatypes.generic.Elements;
import org.json.simple.JSONObject;

import static com.tufin.lib.datatypes.generic.Elements.SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR;

/**
 * Security Policy Violations For Multi Access Request
 *
 * Parse the security policy violation response for multiple access requests based on the USP
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class SecurityPolicyViolationsForMultiAr {
    @JsonProperty("security_policy_violations_for_multi_ar")
    private SecurityPolicyViolationForAr securityPolicyViolationsForAr;

    public SecurityPolicyViolationsForMultiAr(JSONObject json) {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode topElement = mapper.convertValue(json.get(SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR), JsonNode.class);
        JsonNode securityPolicyViolationsForArElement =  topElement.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_AR);
        this.securityPolicyViolationsForAr = new SecurityPolicyViolationForAr(securityPolicyViolationsForArElement);
    }

    public SecurityPolicyViolationForAr getSecurityPolicyViolationsForAr() {
        return securityPolicyViolationsForAr;
    }
}

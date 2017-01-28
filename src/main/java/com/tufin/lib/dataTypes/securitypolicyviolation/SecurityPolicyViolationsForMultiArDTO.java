package com.tufin.lib.dataTypes.securitypolicyviolation;


import org.json.simple.JSONObject;

public class SecurityPolicyViolationsForMultiArDTO {
    private static final String SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR = "security_policy_violations_for_multi_ar";
    private static final String SECURITY_POLICY_VIOLATIONS_FOR_AR = "security_policy_violations_for_ar";
    private SecurityPolicyViolationForArDTO securityPolicyViolationsForAr;

    public SecurityPolicyViolationsForMultiArDTO(JSONObject json) {
//        System.out.println(json.get(SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR));
        JSONObject topElement = (JSONObject) json.get(SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR);
        JSONObject securityPolicyViolationsForArElement =  (JSONObject) topElement.get(SECURITY_POLICY_VIOLATIONS_FOR_AR);
        this.securityPolicyViolationsForAr = new SecurityPolicyViolationForArDTO(securityPolicyViolationsForArElement);
    }

    public SecurityPolicyViolationForArDTO getSecurityPolicyViolationsForAr() {
        return securityPolicyViolationsForAr;
    }
}

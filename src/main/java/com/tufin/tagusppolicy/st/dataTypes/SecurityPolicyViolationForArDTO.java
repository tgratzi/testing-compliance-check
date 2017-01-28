package com.tufin.tagusppolicy.st.dataTypes;

import org.json.simple.JSONObject;


public class SecurityPolicyViolationForArDTO {
    private static final String VIOLATIONS = "violations";
    private static final String ACCESS_REQUEST_ORDER = "access_request_order";
    private static final String SECURITY_POLICY_VIOLATIONS_FOR_AR = "security_policy_violations_for_ar";
    private int access_request_order;
    private ViolationDTO violations;

    public SecurityPolicyViolationForArDTO(JSONObject json) {
        System.out.println("Parsing security policy violation for AR");
        this.access_request_order = Integer.parseInt(json.get(ACCESS_REQUEST_ORDER).toString());
        Object violations = json.get(VIOLATIONS);
        if (violations instanceof String) {
            this.violations = null;
        } else {
            this.violations = new ViolationDTO((JSONObject) json.get(VIOLATIONS));
        }
    }

    public ViolationDTO getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return  (violations != null);
    }
}

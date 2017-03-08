package com.tufin.lib.datatypes.securitypolicyviolation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tufin.lib.datatypes.generic.Elements;
import org.json.simple.JSONObject;

import static com.tufin.lib.datatypes.generic.Elements.VIOLATION;


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

    public SecurityPolicyViolationForAr(JsonNode json) {
        this.access_request_order = Integer.parseInt(json.get(Elements.ACCESS_REQUEST_ORDER).toString());
        JsonNode violations = json.get(Elements.VIOLATIONS);
        if (violations.size() == 0) {
            this.violations = null;
        } else {
            ObjectMapper mapper = new ObjectMapper();
            this.violations = mapper.convertValue(violations.get(VIOLATION), Violation.class);
            try {
                System.out.println(mapper.writeValueAsString(this.violations));
            } catch (JsonProcessingException ex) {
                ex.printStackTrace();
            }
        }
    }

    public Violation getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return  (violations != null);
    }
}

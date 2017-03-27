package com.tufin.lib.datatypes.securitypolicyviolation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tufin.lib.datatypes.generic.Elements;

import java.util.ArrayList;
import java.util.List;

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
    private List<Violation> violations = new ArrayList<>();

    public SecurityPolicyViolationForAr(JsonNode json) {
        this.access_request_order = Integer.parseInt(json.get(Elements.ACCESS_REQUEST_ORDER).toString());
        JsonNode violations = json.get(Elements.VIOLATIONS);
        if (violations.size() == 0) {
            this.violations = null;
        } else {
            ObjectMapper mapper = new ObjectMapper();
            for (JsonNode node: violations.get(VIOLATION)) {
                Violation violation = mapper.convertValue(node, Violation.class);
                this.violations.add(violation);
            }
        }
    }

    public List<Violation> getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return  (violations != null);
    }
}

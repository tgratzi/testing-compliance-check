package com.tufin.lib.helpers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tufin.lib.dataTypes.securitypolicyviolation.SecurityPolicyViolationsForMultiAr;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyDetailedResponse;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyViolationsResponse;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Violation helper
 *
 * Running compliance check both for rules and TAGs.
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class ViolationHelper {
    private static final String USP_URL = "https://{0}/securetrack/api/violations/access_requests/sync.json?use_topology=false&ar_domain_mode=false";
    private static final String TAG_URL = "https://{0}/securetrack/api/tagpolicy/violation_check?policy_external_id=";
    private static final String POLICY_URL = "https://{0}/securetrack/api/tagpolicy/policies/";
    private static final String APPLICATION_XML = "application/xml";
    private static final String APPLICATION_JSON = "application/json";

    private Logger logger;

    public ViolationHelper() {
        logger = Logger.getLogger(ViolationHelper.class.getName());
    }

    public ViolationHelper(Level level, OutputStream outputStream) {
        BuildComplianceLog complianceLog = new BuildComplianceLog(getClass().getName(), level, outputStream);
        this.logger = complianceLog.getLogger();
    }

    public SecurityPolicyViolationsForMultiAr checkUSPAccessRequestViolation(HttpHelper stHelper, String str) throws IOException{
        System.out.println("Checking USP access request violation");
        SecurityPolicyViolationsForMultiAr violationMultiAr = null;
        JSONObject response = stHelper.post(USP_URL, str, APPLICATION_XML);
        violationMultiAr = new SecurityPolicyViolationsForMultiAr(response);
        return violationMultiAr;
    }

    public TagPolicyViolationsResponse checkTagViolation(HttpHelper stHelper, String body, String policyId) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JSONObject response = (JSONObject) stHelper.post(TAG_URL + policyId, body, APPLICATION_JSON);
        JsonNode JsonNodeResponse = mapper.convertValue(response, JsonNode.class);
        TagPolicyViolationsResponse tagPolicyViolationsResponse = new TagPolicyViolationsResponse(JsonNodeResponse);
        return tagPolicyViolationsResponse;
    }

    public TagPolicyDetailedResponse getTagPolicies(HttpHelper stHelper) throws IOException {
        JSONObject response = stHelper.get(POLICY_URL);
        return new TagPolicyDetailedResponse(response);
    }
}

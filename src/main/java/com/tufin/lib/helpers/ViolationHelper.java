package com.tufin.lib.helpers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tufin.lib.dataTypes.accessrequest.AccessRequest;
import com.tufin.lib.dataTypes.securitygroup.SecurityGroup;
import com.tufin.lib.dataTypes.securitypolicyviolation.SecurityPolicyViolationsForMultiAr;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyDetailedResponse;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyViolation;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyViolationsCheckRequest;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyViolationsResponse;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Violation helper
 *
 * Running compliance check both for rules and TAGs.
 *
 * @author Tufin PS-Dev support@tufin.com
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

    private String formatMessage(String securityGroupName, String direction, AccessRequest accessRequest, String status) {
        StringBuffer errorMsg = new StringBuffer();
        errorMsg.append("=====================================================================").append('\n');
        errorMsg.append("Status: ").append(status).append('\n');
        errorMsg.append("Security Group: ").append(securityGroupName).append('\n');
        errorMsg.append("Source: ").append(accessRequest.getSource()).append('\n');
        errorMsg.append("Destination: ").append(accessRequest.getDestination()).append('\n');
        errorMsg.append("Service: ").append(accessRequest.getService()).append('\n');
        errorMsg.append("Direction: ").append(direction).append('\n');
        errorMsg.append("=====================================================================");
        return errorMsg.toString();
    }

    public Boolean checkUspViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper, ViolationHelper violation,
                                      PrintStream logger) throws IOException {
        logger.println("Running compliance check for AWS security group");
        Map<String, List<SecurityGroup>> securityGroupRules = cf.getSecurityGroupRules();
        if (securityGroupRules.isEmpty()) {
            logger.println("No security group was found");
            return false; //If no rules in security group no traffic is allowed
        }
        for(Map.Entry<String, List<SecurityGroup>> securityGroupRule :  securityGroupRules.entrySet()) {
            if (securityGroupRule.getValue().isEmpty()) {
                logger.println(String.format("Could not parse security group '%s'", securityGroupRule.getKey()));
                return true;
            }
            String direction = securityGroupRule.getValue().get(0).getDirection();
            logger.println(String.format("Processing security group '%s'", securityGroupRule.getKey()));
            JaxbAccessRequestBuilder rule = new JaxbAccessRequestBuilder(securityGroupRule);
            for (AccessRequest ar: rule.getAccessRequestList()) {
                String accessRequestStr = rule.accessRequestBuilder(ar);
                SecurityPolicyViolationsForMultiAr violationMultiAr = violation.checkUSPAccessRequestViolation(stHelper, accessRequestStr);
                if (violationMultiAr.getSecurityPolicyViolationsForAr().isViolated()) {
                    logger.println(formatMessage(securityGroupRule.getKey(), direction, ar, "VIOLATION FOUND"));
                    return true;
                }
            }
        }
        logger.println("Compliance check for AWS security groups pass with no violation");
        return false;
    }

    public Boolean checkTagPolicyViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper,
                                            ViolationHelper violation, PrintStream logger, String policyId) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, TagPolicyViolationsCheckRequest> instanceTagsList = cf.getInstancesTags();
        if (instanceTagsList.isEmpty()) {
            logger.println("No Instance TAGs were found in the Cloudformation template");
        } else {
            StringBuffer violationMsg = new StringBuffer();
            for (Map.Entry<String, TagPolicyViolationsCheckRequest> instanceTags : instanceTagsList.entrySet()) {
                String jsonTagPolicyViolation = mapper.writeValueAsString(instanceTags);
                TagPolicyViolationsResponse tagPolicyViolationsResponse = violation.checkTagViolation(stHelper, jsonTagPolicyViolation, policyId);
                if (tagPolicyViolationsResponse.isViolated()) {
                    for (TagPolicyViolation tagViolation: tagPolicyViolationsResponse.getViolations()){
                        violationMsg.append("Instance Name: ").append(instanceTags.getKey()).append(", ");
                        violationMsg.append(tagViolation.toString()).append("\n");
                    }
                }
            }
            if (violationMsg.toString().isEmpty()) {
                logger.println("No instance TAGs violations were found");
            } else {
                logger.print(violationMsg.toString());
                return true;
            }
        }
        return false;
    }
}

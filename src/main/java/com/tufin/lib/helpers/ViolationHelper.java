package com.tufin.lib.helpers;


import com.tufin.lib.dataTypes.securitypolicyviolation.SecurityPolicyViolationsForMultiArDTO;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ViolationHelper {
    private Logger logger;

    public ViolationHelper() {
        logger = Logger.getLogger(ViolationHelper.class.getName());
    }

    public ViolationHelper(Level level, OutputStream outputStream) {
        BuildComplianceLog complianceLog = new BuildComplianceLog(getClass().getName(), level, outputStream);
        this.logger = complianceLog.getLogger();
    }

    public SecurityPolicyViolationsForMultiArDTO checkUSPAccessRequestViolation(HttpHelper stHelper, String str) throws IOException{
        final String uspURL = "https://{0}/securetrack/api/violations/access_requests/sync.json?use_topology=false&ar_domain_mode=false";
        logger.info("Checking USP access request violation");
        JSONObject response = new JSONObject();
        SecurityPolicyViolationsForMultiArDTO violationMultiAr = null;
        response = stHelper.post(uspURL, str);
        violationMultiAr = new SecurityPolicyViolationsForMultiArDTO(response);
        return violationMultiAr;
    }

    public void checkTagViolation(HttpHelper stHelper) throws IOException {
        final String tagURL = "https://{0}/securetrack/api/tagpolicy/violation_check.json?policy_external_id={1}";
        logger.info("Tag Violation");
    }
}

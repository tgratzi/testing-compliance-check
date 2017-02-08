package com.tufin.lib.datatypes.securitypolicyviolation;

import org.json.simple.JSONObject;


/**
 * USP violation information
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class Violation {
    private String severities = null;

    public Violation(JSONObject json) {
        JSONObject violation = new JSONObject();
//        violation = json.get(Elements.VIOLATION);
    }
}

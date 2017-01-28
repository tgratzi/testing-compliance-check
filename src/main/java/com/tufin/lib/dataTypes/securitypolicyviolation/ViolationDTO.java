package com.tufin.lib.dataTypes.securitypolicyviolation;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;


public class ViolationDTO {
    private static final String VIOLATION = "violation";
    private String severities = null;

    public ViolationDTO(JSONObject json) {
        System.out.println("Parsing single violation");
        JSONArray violation = new JSONArray();
        violation = (JSONArray) json.get(VIOLATION);
    }
}

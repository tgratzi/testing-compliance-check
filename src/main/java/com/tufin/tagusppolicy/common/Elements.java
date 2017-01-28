package com.tufin.tagusppolicy.common;


public enum Elements {
    VIOLATIONS("violations"),
    ACCESS_REQUEST_ORDER("access_request_order"),
    SECURITY_POLICY_VIOLATIONS_FOR_AR("security_policy_violations_for_ar");

    String element;
    Elements(String element) {
        this.element = element;
    }

    public static String getValueByElementName(String element) {
        for (Elements el: Elements.values()) {
            String elName = el.getElement();
            if (elName.equalsIgnoreCase(element)) {
                return elName;
            }
        }
        throw new IllegalStateException("No such element: " + element);
    }

    public String getElement() {
        return element;
    }
}

package com.tufin.lib.datatypes.securitypolicyviolation;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;


/**
 * USP violation information
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class Violation {
    @JsonProperty("severity")
    private String severity;

    @JsonProperty("security_zone_matrix")
    private JsonNode securityZoneMatrix;

    @JsonProperty("@xsi.type")
    private String xsiType;

    @JsonProperty("matrix_cell_violation")
    private JsonNode matrixCellViolation;

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public void setSecurityZoneMatrix(JsonNode securityZoneMatrix) {
        this.securityZoneMatrix = securityZoneMatrix;
    }

    public void setXsiType(String xsiType) {
        this.xsiType = xsiType;
    }

    public void setMatrixCellViolation(JsonNode matrixCellViolation) {
        this.matrixCellViolation = matrixCellViolation;
    }
}

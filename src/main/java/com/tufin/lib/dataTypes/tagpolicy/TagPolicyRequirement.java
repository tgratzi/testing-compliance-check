package com.tufin.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.tufin.lib.dataTypes.generic.Elements;

import java.util.ArrayList;
import java.util.List;

/**
 * TAG Policy Requirment
 *
 * Represent the requirements for the TAG policy in the JSON response
 *
 * @author Tzachi Gratziani ps-dev@tufin.com
 */
public class TagPolicyRequirement {
    private String requirementName;
    private String requirementDescription;
    private String requirementType;

    public TagPolicyRequirement() {}

    public TagPolicyRequirement(JsonNode node) {
        this.requirementName = node.get(Elements.REQUIREMENT_NAME).textValue();
        this.requirementType = node.get(Elements.REQUIREMENT_TYPE).textValue();
        this.requirementDescription = node.get(Elements.REQUIREMENT_DESCRIPTION).textValue();
    }

    public String getRequirementType() {
        return requirementType;
    }

    public class MandatoryTagPolicyRequirement extends TagPolicyRequirement {
        private List<String> tags = new ArrayList<String>();

        public MandatoryTagPolicyRequirement(JsonNode node) {
            super(node);
            try {
                JsonNode tagNode = node.get(Elements.TAGS);
                for (int i = 0; i < tagNode.size(); i++)
                    this.tags.add(tagNode.get(i).textValue());
            } catch (Exception ex) {
                System.out.println("tags");
            }
        }

        public List<String> getTags() {
            return tags;
        }
    }

    public class ValidValuesTagPolicyRequirement extends TagPolicyRequirement {
        private String tag;
        private List<String> values = new ArrayList<String>();

        public ValidValuesTagPolicyRequirement(JsonNode node) {
            super(node);
            this.tag = node.get(Elements.TAG).textValue();
            try {
                JsonNode listOfVal = node.get(Elements.VALUES);
                for (int i = 0; i < listOfVal.size(); i++)
                    this.values.add(listOfVal.get(i).textValue());
            } catch (Exception ex) {
                System.out.println("value");
            }
        }

        public String getTag() {
            return tag;
        }

        public List<String> getValues() {
            return values;
        }
    }
}

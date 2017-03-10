package com.tufin.lib.helpers;

import org.junit.Before;
import org.junit.Test;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;

import static org.junit.Assert.*;


public class CloudFormationTemplateProcessorTest {
    private static final String CLOUDFORMATION_TEMPLATE = "cloudformation.json";
    private CloudFormationTemplateProcessor cf;

    @Before
    public void setup() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource(CLOUDFORMATION_TEMPLATE).getFile());
        cf = new CloudFormationTemplateProcessor(file.toString());
        cf.processCF();
    }

    @Test
    public void parseSecurityGroup() throws Exception {
        assertNotNull(cf.getSecurityGroupRules().get("SecurityGroupWithCidrIP"));
        assertNotNull(cf.getSecurityGroupRules().get("SecurityGroupWithCidrIPRef"));
        assertNotNull(cf.getSecurityGroupRules().get("SecurityGroupWithSourceSecurityGroupIdWithDefaultParam"));
        assertNotNull(cf.getSecurityGroupRules().get("SecurityGroupWithCidrIPMutipleIngressObjects"));
        assertNotNull(cf.getSecurityGroupRules().get("SecurityGroupWithNestedSecurityGroup"));
        assertEquals(new ArrayList<String>(), cf.getSecurityGroupRules().get("SecurityGroupWithSourceSecurityGroupIdMissingParam"));
    }

    @Test
    public void parseInstanceTAG() throws Exception {
        assertNotNull(cf.getInstancesTags().get("InstanceWithTAG"));
        assertEquals(new HashMap<String, String>(), cf.getInstancesTags().get("InstanceMissingTAG").getTags());
    }
}
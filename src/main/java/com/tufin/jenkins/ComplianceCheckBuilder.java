package com.tufin.jenkins;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyViolation;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyViolationsCheckRequest;
import com.tufin.lib.dataTypes.tagpolicy.TagPolicyViolationsResponse;
import com.tufin.lib.helpers.CloudFormationTemplateProcessor;
import com.tufin.lib.helpers.JaxbAccessRequestBuilder;
import com.tufin.lib.dataTypes.securitygroup.SecurityGroup;
import com.tufin.lib.dataTypes.accessrequest.AccessRequest;
import com.tufin.lib.helpers.HttpHelper;
import com.tufin.lib.helpers.ViolationHelper;
import com.tufin.lib.dataTypes.securitypolicyviolation.SecurityPolicyViolationsForMultiAr;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Extension;
import hudson.model.*;
import hudson.util.FormValidation;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import org.json.simple.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;


/**
 * Sample {@link Builder}.
 *
 * <p>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked
 * and a new {@link ComplianceCheckBuilder} is created. The created
 * instance is persisted to the project configuration XML by using
 *
 * <p>
 * When a build is performed, the {@link #perform} method will be invoked. 
 *
 * @author Kohsuke Kawaguchi
 */
public class ComplianceCheckBuilder extends Builder {
    private static final transient Logger LOGGER = Logger.getLogger(ComplianceCheckBuilder.class.getName());

    //Below fields are configured via the config.jelly page.
    private boolean useLocalSTCredentials;
    private String host;
    private String username;
    private String password;
    private String policyId;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public ComplianceCheckBuilder(boolean useOwnServerCredentials, final String host, final String username,
                                  final String password, final String policyId) {
        this.useLocalSTCredentials = useOwnServerCredentials;
        this.host = host;
        this.username = username;
        this.password = password;
        this.policyId = policyId;
    }

    /**
     * We'll use this from the {@code config.jelly}.
     */
    public String getHost() {
        return host;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getPolicyId() {
        return policyId;
    }

    private String red(String message) { return "\033[31m" + message + "\033[0m"; }

    private String green(String message) { return "\033[32m" + message + "\033[0m"; }

    private String formatMessage(String securityGroupName, String direction, AccessRequest accessRequest, String status) {
        StringBuffer errorMsg = new StringBuffer();
        errorMsg.append("----------------------------------------------------------------------").append('\n');
        errorMsg.append("Status: ").append(status).append('\n');
        errorMsg.append("Security Group: ").append(securityGroupName).append('\n');
        errorMsg.append("Source: ").append(accessRequest.getSource()).append('\n');
        errorMsg.append("Destination: ").append(accessRequest.getDestination()).append('\n');
        errorMsg.append("Service: ").append(accessRequest.getService()).append('\n');
        errorMsg.append("Direction: ").append(direction).append('\n');
        errorMsg.append("----------------------------------------------------------------------");
        return errorMsg.toString();
    }

    private Boolean checkUspViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper, ViolationHelper violation,
                                   PrintStream logger) throws IOException {
        logger.println("Getting list of AWS security group CF object");
        Map<String, List<SecurityGroup>> securityGroupRules = cf.getSecurityGroupRules();
        if (securityGroupRules.isEmpty()) {
            logger.println("No security group was found");
            return false;
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
                logger.println(formatMessage(securityGroupRule.getKey(), direction, ar, "No violation found"));
            }
        }
        logger.println("Compliance check for AWS security groups pass with no violation");
        return false;
    }

    private Boolean checkTagPolicyViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper,
                                         ViolationHelper violation, PrintStream logger, String policyId) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        List<TagPolicyViolationsCheckRequest> instanceTagsList = cf.getInstancesTags();
        if (instanceTagsList.isEmpty()) {
            logger.println("No Instance TAGs were found in the Cloudformation template");
        } else {
            StringBuffer violationMsg = new StringBuffer();
            for (TagPolicyViolationsCheckRequest instanceTags : instanceTagsList) {
                String jsonTagPolicyViolation = mapper.writeValueAsString(instanceTags);
                TagPolicyViolationsResponse tagPolicyViolationsResponse = violation.checkTagViolation(stHelper, jsonTagPolicyViolation, policyId);
                if (tagPolicyViolationsResponse.isViolated()) {
                    for (TagPolicyViolation tagViolation: tagPolicyViolationsResponse.getViolations())
                        violationMsg.append(tagViolation.toString()).append("\n");
                }
            }
            if (violationMsg.toString().isEmpty()) {
                logger.println("No instance TAG violation found");
            } else {
                logger.print(violationMsg.toString());
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws IOException, InterruptedException {
        final DescriptorImpl descriptor = getDescriptor();
        try {
            PrintStream logger = listener.getLogger();
            final String password = this.password.isEmpty() ? descriptor.getPassword() : this.password ;
            logger.println("Reading the Cloudformation JSON files");
            List<FilePath> buildFiles = build.getWorkspace().list();
            logger.println(String.format("Build HTTP connection to host '%s'", host));
            logger.println(String.format("Build HTTP connection to host '%s'", policyId));
            HttpHelper stHelper = new HttpHelper(host, password, username);
            for (FilePath filePath: buildFiles) {
                if (!filePath.getName().toLowerCase().endsWith(".json")) {continue;}
                ViolationHelper violation = new ViolationHelper();
                logger.println(String.format("Compliance check for Cloudformation template '%s'", filePath.getName()));
                CloudFormationTemplateProcessor cf = new CloudFormationTemplateProcessor(filePath.getRemote());
                logger.println("Check USP violation for AWS security groups");
                if (checkUspViolation(cf, stHelper, violation, logger)) {
                    return false;
                }
                logger.println("Check policy TAGs violations for AWS Instance");
                if (checkTagPolicyViolation(cf, stHelper, violation, logger, policyId)) {
                    return false;
                }
            }
            logger.println(green("No violations were found, GOOD TO GO"));
            return true;
        } catch (IOException ex) {
                throw ex;
        }
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    /**
     * Descriptor for {@link ComplianceCheckBuilder}. Used as a singleton.
     * The class is marked as public so that it can be accessed from views.
     *
     * <p>
     * See {@code src/main/resources/hudson/plugins/hello_world/ComplianceCheckBuilder/*.jelly}
     * for the actual HTML fragment for the configuration screen.
     */
    @Extension // This indicates to Jenkins that this is an implementation of an extension point.
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        private String host;
        private String username;
        private String password;
        private Boolean enabled;

        public DescriptorImpl() {
            load();
        }

        @Override
        public boolean configure(StaplerRequest req, net.sf.json.JSONObject formData) throws FormException {
//            host = formData.getString("host");
//            username = formData.getString("username");
//            password = formData.getString("password");
            req.bindJSON(this, formData.getJSONObject("tufin"));
            req.bindJSON(this, formData);
            save();
            return super.configure(req, formData);
        }

        public String getHost() {
            return host;
        }

        public void setHost(@Nullable String host) {
            this.host = host;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(@Nullable String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(@Nullable String password) {
            this.password = password;
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Tufin Compliance Check";
        }

        @Override
        public String getHelpFile() {
            return "/plugin/tufin-compliance-check/help.html";
        }

        public FormValidation doCheckUsername(@QueryParameter String value) {
            if (value.length() == 0)
                return FormValidation.error("Please enter a valid username");
            return FormValidation.ok();
        }

        public FormValidation doCheckPassword(@QueryParameter String value) {
            if (value.length() == 0)
                return FormValidation.error("Please enter the corresponding password");
            return FormValidation.ok();
        }

        public FormValidation doCheckHost(@QueryParameter String value) {
            if (value.length() == 0) {
                return FormValidation.error("Please enter a host, either alias, fulle domain name or IP address");
//            } else {
//                try {
//                    SubnetUtils network = new SubnetUtils(value + "/32");
//                } catch (IllegalArgumentException ex) {
//                    System.out.println("IP address is invalid, Error " + ex.getMessage());
//                    return FormValidation.error("IP address is invalid, Error " + ex.getMessage());
//                }
            }
            return FormValidation.ok();
        }

        public FormValidation doTestTufinConnection(@QueryParameter("host") final String host,
                                                    @QueryParameter("username") final String username,
                                                    @QueryParameter("password") final String password) throws IOException {
            final String DOMAINS_URL = "https://{0}/securetrack/api/domains.json";
            HttpHelper stHelper = new HttpHelper(host, password, username);
            JSONObject response =  stHelper.get(DOMAINS_URL);
            if (response != null) {
                return FormValidation.ok("Connection successful");
            }
            return FormValidation.error("Connection could not be established " + response.toString());
        }

        public ListBoxModel doFillPolicyIdItems(@QueryParameter("host") final String host,
                                                @QueryParameter("username") final String username,
                                                @QueryParameter("password") final String password) throws IOException {
            ListBoxModel m = new ListBoxModel();
            try {
                HttpHelper stHelper = new HttpHelper(host, password, username);
                Map<String, String> policiesNameID = new ViolationHelper().getTagPolicies(stHelper).getPolicies();
                m.add("","");
                for (Map.Entry<String,String> policyNameId: policiesNameID.entrySet())
                    m.add(policyNameId.getKey(),policyNameId.getValue());
                return m;
            } catch (Exception e) {
                String message = "Provide Tufin server credentials to see policy list";
                m.add(new ListBoxModel.Option(message, message));
                return m; // Return empty list of project names
            }
        }
    }
}


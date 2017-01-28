package com.tufin.jenkins;

import com.tufin.tagusppolicy.cf.CloudFormationTemplateProcessor;
import com.tufin.tagusppolicy.cf.JaxbAccessRequestBuilder;
import com.tufin.tagusppolicy.cf.dataTypes.json.SecurityGroup;
import com.tufin.tagusppolicy.cf.dataTypes.xml.AccessRequest;
import com.tufin.tagusppolicy.common.HttpHelper;
import com.tufin.tagusppolicy.st.ViolationHelper;
import com.tufin.tagusppolicy.st.dataTypes.SecurityPolicyViolationsForMultiArDTO;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Extension;
import hudson.model.*;
import hudson.util.FormValidation;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import org.apache.commons.net.util.SubnetUtils;
import org.json.simple.parser.ParseException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
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
    private String ip;
    private String username;
    private String password;
    private Integer policyId;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public ComplianceCheckBuilder(final String ip, final String username,
                                  final String password, final Integer policyId) {
        this.ip = ip;
        this.username = username;
        this.password = password;
        this.policyId = policyId;
        LOGGER.info(ip);
    }

    /**
     * We'll use this from the {@code config.jelly}.
     */
    public String getIp() {
        return ip;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Integer getPolicyId() {
        return policyId;
    }

    private String red(String message) { return "\033[31m" + message + "\033[0m"; }

    private String green(String message) { return "\033[32m" + message + "\033[0m"; }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws IOException, InterruptedException {
        try {
            PrintStream logger = listener.getLogger();
            logger.println("Reading the Cloudformation JSON file");
            List<FilePath> buildFiles = build.getWorkspace().list();
            for (FilePath filePath: buildFiles) {
                if (!filePath.getName().toLowerCase().endsWith(".json")) {
                    continue;
                }

                logger.println("Checking template '" + filePath.getName() + "' for USP compliance.");
                ViolationHelper violation = new ViolationHelper();
                CloudFormationTemplateProcessor cf = new CloudFormationTemplateProcessor(filePath.getRemote());
                for (Map.Entry<String, List<SecurityGroup>> securityGroupRule : cf.securityGroupRules.entrySet()) {
                    JaxbAccessRequestBuilder rule = new JaxbAccessRequestBuilder(securityGroupRule);
                    for (AccessRequest ar: rule.getAccessRequestList()) {
                        String accessRequestStr = rule.accessRequestBuilder(ar);
                        HttpHelper stHelper = new HttpHelper("192.168.204.161", "tzachi", "tzachi");
                        SecurityPolicyViolationsForMultiArDTO violationMultiAr = violation.checkUSPAccessRequestViolation(stHelper, accessRequestStr);
                        if (violationMultiAr.getSecurityPolicyViolationsForAr().isViolated()) {
                            System.out.println(red("Violation was found"));
                            System.out.println("Security Group: " + securityGroupRule.getKey());
                            System.out.println("Source: " + ar.getSource());
                            System.out.println("Destination: " + ar.getDestination());
                            System.out.println("Service: " + ar.getService());
                        }
                    }
                }
            }
            logger.println(green("No violations were found, good to go"));
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
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project types
            return true;
        }

        @Override
        public String getDisplayName() {
            LOGGER.info("Display name for tufin compliance check plugin");
            return "Tufin Compliance Check";
        }

        @Override
        public String getHelpFile() {
            return "/plugin/tufin-compliance-check/help.html";
        }

        public FormValidation doCheckUsername(@QueryParameter String value) throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set a username");
            return FormValidation.ok();
        }

        public FormValidation doCheckPassword(@QueryParameter String value) throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set a password");
            return FormValidation.ok();
        }

        public FormValidation doCheckIp(@QueryParameter String value) {
            if (value.length() == 0) {
                return FormValidation.error("Please set an IP");
            } else {
                try {
                    SubnetUtils network = new SubnetUtils(value + "/32");
                } catch (IllegalArgumentException ex) {
                    System.out.println("IP address is invalid, Error " + ex.getMessage());
                    return FormValidation.error("IP address is invalid, Error " + ex.getMessage());
                }
            }
            return FormValidation.ok();
        }

        public FormValidation doTestTufinConnection(@QueryParameter("ip") final String host,
                                                    @QueryParameter("username") final String username,
                                                    @QueryParameter("password") final String password) {
            final String DOMAINS_URL = "https://{0}/securetrack/api/domains.json";
            HttpHelper stHelper = new HttpHelper(host, password, username);
            try {
                org.json.simple.JSONObject response =  stHelper.get(DOMAINS_URL);
                if (! response.isEmpty()) {
                    return FormValidation.ok("Connection successful");
                } else {
                    return FormValidation.error("Connection could not be established " + response.toString());
                }
            } catch (ParseException ex) {

            }
            return FormValidation.ok();
        }

        /**
         * This method returns true if the global configuration says we should speak French.
         *
         * The method name is bit awkward because global.jelly calls this method to determine
         * the initial state of the checkbox by the naming convention.
         */
        public boolean getUseFrench() {
            return true;
        }
    }
}


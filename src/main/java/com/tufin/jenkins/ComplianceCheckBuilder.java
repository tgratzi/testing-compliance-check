package com.tufin.jenkins;

import com.tufin.lib.helpers.CloudFormationTemplateProcessor;
import com.tufin.lib.helpers.HttpHelper;
import com.tufin.lib.helpers.ViolationHelper;
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
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
    private String jsonPath;
    private String severity;
    private String environment;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public ComplianceCheckBuilder(boolean useOwnServerCredentials, final String host, final String username,
                                  final String password, final String policyId, String jsonPath, String severity,
                                  String environment) {
        this.useLocalSTCredentials = useOwnServerCredentials;
        this.host = host;
        this.username = username;
        this.password = password;
        this.policyId = policyId;
        setJsonPath(jsonPath);
        setSeverity(severity);
        setEnvironment(environment);
    }

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

    public String getJsonPath() {
        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {
        this.jsonPath = jsonPath;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getEnvironment() {
        return environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    private String red(String message) { return "\033[31m" + message + "\033[0m"; }

    private String green(String message) { return "\033[32m" + message + "\033[0m"; }

    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws IOException, InterruptedException {
        final DescriptorImpl descriptor = getDescriptor();
        PrintStream logger = listener.getLogger();
        try {
            logger.println(severity);
            ViolationHelper violation = new ViolationHelper(logger);
            logger.println(String.format("Building HTTP connection to host '%s'", host));
            HttpHelper stHelper = new HttpHelper(host, password, username);
            String dirPath = build.getWorkspace().getRemote();
            if (! jsonPath.equalsIgnoreCase(".") && ! jsonPath.isEmpty()) {
                dirPath += jsonPath;
                if (! Files.isDirectory(Paths.get(dirPath))) {
                    System.out.println("Not a directory " + dirPath);
                    return false;
                }
            }

            Path currentPath = Paths.get(dirPath);
            DirectoryStream<Path> files = Files.newDirectoryStream(currentPath, "*.json");
            for (Path filePath: files) {
                logger.println(String.format("Compliance check for Cloudformation template '%s'", filePath.getFileName()));
                CloudFormationTemplateProcessor cf = new CloudFormationTemplateProcessor(filePath.toString(), logger);
                try {
                    cf.processCF();
                } catch (IOException ex) {
                    logger.println(ex.getMessage());
                    if (severity.equalsIgnoreCase("critical")) {
                        return true;
                    }
                    continue;
                }
                if (cf.getIsCloudformation()) {
                    logger.println("Checking USP violation for AWS security groups");
                    if (violation.checkUspViolation(cf, stHelper, violation)) {
                        logger.println("----------------------------------------------------------------------");
                        return false;
                    }
                    logger.println("Checking policy TAGs violation for AWS Instances");
                    Boolean isViolated = violation.checkTagPolicyViolation(cf, stHelper, violation, policyId);
                    if (isViolated && severity.equalsIgnoreCase("critical")) {
                        logger.println("----------------------------------------------------------------------");
                        return false;
                    }
                    logger.println("----------------------------------------------------------------------");
                } else {
                    logger.println("The Json file is not a Cloudformation template, skip");
                    logger.println("----------------------------------------------------------------------");
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
                return FormValidation.error("Please enter a host, either alias, full domain name or IP address");
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

        public ListBoxModel doFillSeverityItems() throws IOException {
            ListBoxModel m = new ListBoxModel();
            m.add("Critical", "critical");
            m.add("Major", "major");
            m.add("low", "low");
            return m;
        }

        public ListBoxModel doFillEnvironmentItems() throws IOException {
            ListBoxModel m = new ListBoxModel();
            m.add("Production", "production");
            m.add("Test", "test");
            return m;
        }
    }
}


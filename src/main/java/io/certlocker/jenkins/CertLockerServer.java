package io.certlocker.jenkins;

import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.net.URI;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/** Administrator-owned destination and OIDC credential selection. */
public final class CertLockerServer extends AbstractDescribableImpl<CertLockerServer> {
    private final String name;
    private final String url;
    private final String credentialsId;
    private String account;

    public String getAccount() {
        return account;
    }

    @DataBoundSetter
    public void setAccount(String account) {
        this.account = account == null || account.isBlank() ? null : SecretBinding.pathId(account);
    }

    @DataBoundConstructor
    public CertLockerServer(String name, String url, String credentialsId) {
        if (name == null || !name.matches("[A-Za-z0-9_.-]+")) {
            throw new IllegalArgumentException(
                    "CertLocker server name must use letters, digits, dot, dash or underscore");
        }
        endpoint(url);
        if (credentialsId == null || credentialsId.isBlank()) {
            throw new IllegalArgumentException("An OIDC provider credential ID is required");
        }
        this.name = name;
        this.url = url.replaceAll("/+$", "");
        this.credentialsId = credentialsId;
    }

    static URI endpoint(String baseUrl) {
        try {
            URI uri = URI.create(baseUrl);
            if (!"https".equals(uri.getScheme())
                    || uri.getHost() == null
                    || uri.getUserInfo() != null
                    || uri.getQuery() != null
                    || uri.getFragment() != null
                    || uri.getPort() == 0
                    || uri.getPort() > 65535
                    || !uri.normalize().equals(uri)) {
                throw new IllegalArgumentException();
            }
            return URI.create(baseUrl.replaceAll("/+$", "") + "/rest/api/v1/oidc/exchange");
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(
                    "CertLocker URL must be an absolute HTTPS base URL without user info, query or fragment");
        }
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<CertLockerServer> {
        public FormValidation doCheckName(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (value == null || !value.matches("[A-Za-z0-9_.-]+")) {
                return FormValidation.error(
                        "Use letters, digits, dot, dash or underscore, for example local-trust. Spaces are not allowed.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            try {
                endpoint(value);
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error(e.getMessage());
            }
        }

        public FormValidation doCheckCredentialsId(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return value == null || value.isBlank()
                    ? FormValidation.error("Enter the ID of an OpenID Connect id token (string) credential.")
                    : FormValidation.ok();
        }

        public FormValidation doCheckAccount(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            try {
                if (value != null && !value.isBlank()) {
                    SecretBinding.pathId(value);
                }
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error("Enter a Trust account ID, not its display name or a URL.");
            }
        }

        @Override
        public String getDisplayName() {
            return "CertLocker server";
        }
    }
}

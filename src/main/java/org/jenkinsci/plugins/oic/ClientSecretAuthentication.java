package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Authenticates to the token endpoint using a shared client secret (the classic OAuth2
 * {@code client_secret} authentication).
 */
public class ClientSecretAuthentication extends OicClientAuthentication {

    private static final long serialVersionUID = 1L;

    private static final String NO_SECRET = "none";

    private final Secret clientSecret;

    @DataBoundConstructor
    public ClientSecretAuthentication(Secret clientSecret) {
        this.clientSecret = clientSecret;
    }

    @NonNull
    public Secret getClientSecret() {
        return clientSecret == null ? Secret.fromString(NO_SECRET) : clientSecret;
    }

    @Override
    protected void configure(@NonNull OidcConfiguration oidcConfiguration) {
        oidcConfiguration.setSecret(getClientSecret().getPlainText());
    }

    @Extension
    @Symbol("secret")
    public static class DescriptorImpl extends Descriptor<OicClientAuthentication> {

        @Override
        public String getDisplayName() {
            return Messages.ClientSecretAuthentication_DisplayName();
        }

        @RequirePOST
        public FormValidation doCheckClientSecret(@QueryParameter String clientSecret) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(clientSecret) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_ClientSecretRequired());
            }
            return FormValidation.ok();
        }
    }
}

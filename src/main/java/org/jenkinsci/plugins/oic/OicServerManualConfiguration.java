package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Descriptor.FormException;
import hudson.util.FormValidation;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;
import java.util.Objects;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.oic.OicSecurityRealm.TokenAuthMethod;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class OicServerManualConfiguration extends OicServerConfiguration {

    private static final long serialVersionUID = 1L;

    private final String authorizationServerUrl;
    private final String tokenServerUrl;
    private TokenAuthMethod tokenAuthMethod = TokenAuthMethod.client_secret_post;
    private String jwksServerUrl;
    private String endSessionUrl;
    private String scopes = "openid email";
    private String userInfoServerUrl;
    private boolean useRefreshTokens;
    private String issuer;

    @DataBoundConstructor
    public OicServerManualConfiguration(String tokenServerUrl, String authorizationServerUrl) throws FormException {
        this.authorizationServerUrl = validateNonNull("authorizationServerUrl", authorizationServerUrl);
        this.tokenServerUrl = validateNonNull("tokenServerUrl", tokenServerUrl);
    }

    @DataBoundSetter
    public void setTokenAuthMethod(TokenAuthMethod tokenAuthMethod) throws FormException {
        this.tokenAuthMethod = validateNonNull("tokenAuthMethod", tokenAuthMethod);
    }

    @DataBoundSetter
    public void setEndSessionUrl(@Nullable String endSessionUrl) {
        this.endSessionUrl = endSessionUrl;
    }

    @DataBoundSetter
    public void setIssuer(@Nullable String issuer) {
        this.issuer = Util.fixEmptyAndTrim(issuer);
    }

    @DataBoundSetter
    public void setJwksServerUrl(@Nullable String jwksServerUrl) {
        this.jwksServerUrl = jwksServerUrl;
    }

    @DataBoundSetter
    public void setScopes(@NonNull String scopes) {
        this.scopes = Objects.requireNonNull(scopes);
    }

    @DataBoundSetter
    public void setUserInfoServerUrl(@Nullable String userInfoServerUrl) {
        this.userInfoServerUrl = userInfoServerUrl;
    }

    @DataBoundSetter
    public void setUseRefreshTokens(boolean useRefreshTokens) {
        this.useRefreshTokens = useRefreshTokens;
    }

    @Override
    public String getAuthorizationServerUrl() {
        return authorizationServerUrl;
    }

    @Override
    @CheckForNull
    public String getEndSessionUrl() {
        return endSessionUrl;
    }

    @Override
    @CheckForNull
    public String getIssuer() {
        return issuer;
    }

    @Override
    public boolean isUseRefreshTokens() {
        return useRefreshTokens;
    }

    @Override
    public String getJwksServerUrl() {
        return jwksServerUrl;
    }

    @Override
    public String getScopes() {
        return scopes;
    }

    @Override
    public TokenAuthMethod getTokenAuthMethod() {
        return tokenAuthMethod;
    }

    @Override
    public String getTokenServerUrl() {
        return tokenServerUrl;
    }

    @Override
    public String getUserInfoServerUrl() {
        return userInfoServerUrl;
    }

    private static <T> T validateNonNull(String fieldName, T value) throws FormException {
        if (value == null) {
            throw new FormException(fieldName + " is mandatory", fieldName);
        }
        return value;
    }

    @Extension
    @Symbol("manual")
    public static class DescriptorImpl extends Descriptor<OicServerConfiguration> {

        @Override
        public String getDisplayName() {
            return Messages.OicServerManualConfiguration_DisplayName();
        }

        @POST
        public FormValidation doCheckAuthorizationServerUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (value == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenServerURLKeyRequired());
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckEndSessionUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_EndSessionURLKeyRequired());
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckIssuer(@QueryParameter String issuer) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(issuer) == null) {
                return FormValidation.warning(Messages.OicSecurityRealm_IssuerRecommended());
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckJwksServerUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.ok();
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckScopes(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_ScopesRequired());
            }
            if (!value.toLowerCase(Locale.ROOT).contains("openid")) {
                return FormValidation.warning(Messages.OicSecurityRealm_RUSureOpenIdNotInScope());
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckTokenServerUrl(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenServerURLKeyRequired());
            }
            try {
                new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, Messages.OicSecurityRealm_NotAValidURL());
            }
        }

        @POST
        public FormValidation doCheckTokenAuthMethod(@QueryParameter String tokenAuthMethod) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (Util.fixEmptyAndTrim(tokenAuthMethod) == null) {
                return FormValidation.error(Messages.OicSecurityRealm_TokenAuthMethodRequired());
            }
            return FormValidation.ok();
        }
    }
}

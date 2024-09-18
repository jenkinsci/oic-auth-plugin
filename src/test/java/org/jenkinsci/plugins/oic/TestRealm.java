package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import io.burt.jmespath.Expression;
import java.io.IOException;
import java.io.ObjectStreamException;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;

public class TestRealm extends OicSecurityRealm {

    public static final String CLIENT_ID = "clientId";
    public static final String EMAIL_FIELD = "email";
    public static final String FULL_NAME_FIELD = "fullName";
    public static final String GROUPS_FIELD = "groups";

    public static class Builder {
        public String clientId = CLIENT_ID;
        public Secret clientSecret = Secret.fromString("secret");
        public String wellKnownOpenIDConfigurationUrl;
        public String tokenServerUrl;
        public String jwksServerUrl = null;
        public TokenAuthMethod tokenAuthMethod = TokenAuthMethod.client_secret_post;
        public String authorizationServerUrl;
        public String userInfoServerUrl = null;
        public String userNameField = null;
        public String tokenFieldToCheckKey = null;
        public String tokenFieldToCheckValue = null;
        public String fullNameFieldName = FULL_NAME_FIELD;
        public String emailFieldName = null;
        public String scopes = null;
        public String groupsFieldName = null;
        public boolean disableSslVerification = false;
        public Boolean logoutFromOpenidProvider = false;
        public String endSessionEndpoint = null;
        public String postLogoutRedirectUrl = null;
        public boolean escapeHatchEnabled = false;
        public String escapeHatchUsername = null;
        public Secret escapeHatchSecret = null;
        public String escapeHatchGroup = null;
        public boolean automanualconfigure = false;

        public Builder(WireMockRule wireMockRule) throws IOException {
            this("http://localhost:" + wireMockRule.port() + "/");
        }

        public Builder(String rootUrl) throws IOException {
            this.wellKnownOpenIDConfigurationUrl = rootUrl + "well.known";
            this.tokenServerUrl = rootUrl + "token";
            this.authorizationServerUrl = rootUrl + "authorization";
        }

        public Builder WithClient(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret == null ? null : Secret.fromString(clientSecret);
            return this;
        }

        public Builder WithUserInfoServerUrl(String userInfoServerUrl) {
            this.userInfoServerUrl = userInfoServerUrl;
            return this;
        }

        public Builder WithJwksServerUrl(String jwksServerUrl) {
            this.jwksServerUrl = jwksServerUrl;
            return this;
        }

        public Builder WithEmailFieldName(String emailFieldName) {
            this.emailFieldName = emailFieldName;
            return this;
        }

        public Builder WithGroupsFieldName(String groupsFieldName) {
            this.groupsFieldName = groupsFieldName;
            return this;
        }

        public Builder WithPostLogoutRedirectUrl(String postLogoutRedirectUrl) {
            this.postLogoutRedirectUrl = postLogoutRedirectUrl;
            return this;
        }

        public Builder WithAutomanualconfigure(boolean automanualconfigure) {
            this.automanualconfigure = automanualconfigure;
            return this;
        }

        public Builder WithScopes(String scopes) {
            this.scopes = scopes;
            return this;
        }

        public Builder WithMinimalDefaults() {
            return this.WithEmailFieldName(EMAIL_FIELD).WithGroupsFieldName(GROUPS_FIELD);
        }

        public Builder WithLogout(Boolean logoutFromOpenidProvider, String endSessionEndpoint) {
            this.logoutFromOpenidProvider = logoutFromOpenidProvider;
            this.endSessionEndpoint = endSessionEndpoint;
            return this;
        }

        public Builder WithEscapeHatch(
                boolean escapeHatchEnabled,
                String escapeHatchUsername,
                String escapeHatchSecret,
                String escapeHatchGroup) {
            this.escapeHatchEnabled = escapeHatchEnabled;
            this.escapeHatchUsername = escapeHatchUsername;
            this.escapeHatchSecret = escapeHatchSecret == null ? null : Secret.fromString(escapeHatchSecret);
            this.escapeHatchGroup = escapeHatchGroup;
            return this;
        }

        public TestRealm build() throws IOException {
            return new TestRealm(this);
        }

        public OicServerConfiguration buildServerConfiguration() {
            try {
                if (automanualconfigure) {
                    OicServerWellKnownConfiguration conf =
                            new OicServerWellKnownConfiguration(wellKnownOpenIDConfigurationUrl);
                    if (scopes != null) {
                        conf.setScopesOverride(scopes);
                    }
                    return conf;
                }
                OicServerManualConfiguration conf =
                        new OicServerManualConfiguration(tokenServerUrl, authorizationServerUrl);
                conf.setTokenAuthMethod(tokenAuthMethod);
                conf.setUserInfoServerUrl(userInfoServerUrl);
                if (scopes != null) {
                    conf.setScopes(scopes);
                }
                conf.setJwksServerUrl(jwksServerUrl);
                conf.setEndSessionUrl(endSessionEndpoint);
                return conf;
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        }
    }

    public TestRealm(Builder builder) throws IOException {
        super(
                builder.clientId,
                builder.clientSecret,
                builder.buildServerConfiguration(),
                builder.disableSslVerification);
        this.setUserNameField(builder.userNameField);
        this.setTokenFieldToCheckKey(builder.tokenFieldToCheckKey);
        this.setTokenFieldToCheckValue(builder.tokenFieldToCheckValue);
        this.setFullNameFieldName(builder.fullNameFieldName);
        this.setEmailFieldName(builder.emailFieldName);
        this.setGroupsFieldName(builder.groupsFieldName);
        this.setLogoutFromOpenidProvider(builder.logoutFromOpenidProvider);
        this.setPostLogoutRedirectUrl(builder.postLogoutRedirectUrl);
        this.setEscapeHatchEnabled(builder.escapeHatchEnabled);
        this.setEscapeHatchUsername(builder.escapeHatchUsername);
        this.setEscapeHatchSecret(builder.escapeHatchSecret);
        this.setEscapeHatchGroup(builder.escapeHatchGroup);
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl, String emailFieldName, String groupsFieldName)
            throws IOException {
        this(new Builder(wireMockRule)
                .WithUserInfoServerUrl(userInfoServerUrl)
                        .WithEmailFieldName(emailFieldName)
                        .WithGroupsFieldName(groupsFieldName));
    }

    public TestRealm(WireMockRule wireMockRule) throws IOException {
        this(new Builder(wireMockRule).WithMinimalDefaults());
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl) throws IOException {
        this(new Builder(wireMockRule).WithMinimalDefaults().WithUserInfoServerUrl(userInfoServerUrl));
    }

    public TestRealm(
            WireMockRule wireMockRule,
            String userInfoServerUrl,
            String emailFieldName,
            String groupFieldName,
            boolean automanualconfigure)
            throws IOException {
        this(new Builder(wireMockRule)
                .WithMinimalDefaults()
                        .WithUserInfoServerUrl(userInfoServerUrl)
                        .WithEmailFieldName(emailFieldName)
                        .WithGroupsFieldName(groupFieldName)
                        .WithAutomanualconfigure(automanualconfigure));
    }

    public TestRealm(
            WireMockRule wireMockRule,
            String userInfoServerUrl,
            String emailFieldName,
            String groupFieldName,
            boolean automanualconfigure,
            boolean escapeHatchEnabled,
            String escapeHatchUsername,
            String escapeHatchSecret,
            String escapeHatchGroup)
            throws IOException {
        this(new Builder(wireMockRule)
                .WithMinimalDefaults()
                        .WithUserInfoServerUrl(userInfoServerUrl)
                        .WithEmailFieldName(emailFieldName)
                        .WithGroupsFieldName(groupFieldName)
                        .WithAutomanualconfigure(automanualconfigure)
                        .WithEscapeHatch(escapeHatchEnabled, escapeHatchUsername, escapeHatchSecret, escapeHatchGroup));
    }

    @Override
    public Descriptor<SecurityRealm> getDescriptor() {
        return new DescriptorImpl();
    }

    @Override
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        OicSession.getCurrent().state = "state";
        if (!isNonceDisabled()) {
            OicSession.getCurrent().nonce = "nonce";
        }
        return super.doFinishLogin(request);
    }

    public String getStringFieldFromJMESPath(Object object, String jmespathField) {
        Expression<Object> expr = super.compileJMESPath(jmespathField, "test field");
        if (expr == null) {
            return null;
        }
        return super.getStringField(object, expr);
    }

    @Override
    public Object readResolve() throws ObjectStreamException {
        return super.readResolve();
    }

    public boolean doCheckEscapeHatch(String username, String password) {
        return super.checkEscapeHatch(username, password);
    }
}

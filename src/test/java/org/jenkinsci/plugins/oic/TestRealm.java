package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import io.burt.jmespath.Expression;
import java.io.IOException;
import java.io.ObjectStreamException;
import java.io.Serial;
import java.text.ParseException;
import java.util.List;
import jenkins.model.IdStrategy;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.pac4j.core.context.FrameworkParameters;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.JEEFrameworkParameters;
import org.pac4j.jee.context.session.JEESessionStoreFactory;
import org.pac4j.oidc.client.OidcClient;

public class TestRealm extends OicSecurityRealm {

    public static final String CLIENT_ID = "clientId";
    public static final String EMAIL_FIELD = "email";
    public static final String FULL_NAME_FIELD = "fullName";
    public static final String GROUPS_FIELD = "groups";
    public static final String ISSUER = "https://localhost/";

    public static class Builder {
        public String clientId = CLIENT_ID;
        public Secret clientSecret = Secret.fromString("secret");
        public String issuer = ISSUER;
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
        public List<LoginQueryParameter> loginQueryParameters = null;
        public List<LogoutQueryParameter> logoutQueryParameters = null;
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
        public boolean disableTokenValidation = true; // opt in for some specific tests
        public boolean disableTokenExpiration = false;
        public IdStrategy userIdStrategy;
        public IdStrategy groupIdStrategy;
        public boolean allowJWTBearerTokenAccess = false;

        public Builder(WireMockExtension wireMock, boolean useTLS) throws IOException {
            this(
                    useTLS
                            ? "https://localhost:" + wireMock.getHttpsPort() + "/"
                            : "http://localhost:" + wireMock.getPort() + "/");
        }

        public Builder(WireMockExtension wireMock) throws IOException {
            this(wireMock, false);
        }

        public Builder(String rootUrl) {
            this.wellKnownOpenIDConfigurationUrl = rootUrl + "well.known";
            this.tokenServerUrl = rootUrl + "token";
            this.authorizationServerUrl = rootUrl + "authorization";
        }

        public Builder WithClient(String clientId, String clientSecret) {
            this.clientId = clientId;
            this.clientSecret = clientSecret == null ? null : Secret.fromString(clientSecret);
            return this;
        }

        public Builder WithIssuer(String issuer) {
            this.issuer = issuer;
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

        public Builder WithLoginQueryParameters(List<LoginQueryParameter> values) {
            this.loginQueryParameters = values;
            return this;
        }

        public Builder WithLogoutQueryParameters(List<LogoutQueryParameter> values) {
            this.logoutQueryParameters = values;
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

        public Builder WithDisableTokenValidation(boolean disableTokenValidation) {
            this.disableTokenValidation = disableTokenValidation;
            return this;
        }

        public Builder WithDisableTokenExpiration(boolean disableTokenExpiration) {
            this.disableTokenExpiration = disableTokenExpiration;
            return this;
        }

        public Builder WithDisableSslVerification(boolean disableSslVerification) {
            this.disableSslVerification = disableSslVerification;
            return this;
        }

        public Builder WithUserIdStrategy(IdStrategy userIdStrategy) {
            this.userIdStrategy = userIdStrategy;
            return this;
        }

        public Builder WithGroupIdStrategy(IdStrategy groupIdStrategy) {
            this.groupIdStrategy = groupIdStrategy;
            return this;
        }

        public Builder WithAllowJWTBearerTokenAccess(boolean allowJWTBearerTokenAccess) {
            this.allowJWTBearerTokenAccess = allowJWTBearerTokenAccess;
            return this;
        }

        public TestRealm build() throws Exception {
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
                        new OicServerManualConfiguration(issuer, tokenServerUrl, authorizationServerUrl);
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

    public TestRealm(Builder builder) throws Exception {
        super(
                builder.clientId,
                builder.clientSecret,
                builder.buildServerConfiguration(),
                builder.disableSslVerification,
                builder.userIdStrategy,
                builder.groupIdStrategy);
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
        this.setDisableTokenVerification(builder.disableTokenValidation);
        this.setTokenExpirationCheckDisabled(builder.disableTokenExpiration);
        this.setLoginQueryParameters(builder.loginQueryParameters);
        this.setLogoutQueryParameters(builder.logoutQueryParameters);
        this.setAllowJWTBearerTokenAccess(builder.allowJWTBearerTokenAccess);
        // need to call the following method annotated with @PostConstruct and called
        // from readResolve and as such
        // is only called in regular use not code use.
        super.createProxyAwareResourceRetriver();
    }

    public TestRealm(
            WireMockExtension wireMock, String userInfoServerUrl, String emailFieldName, String groupsFieldName)
            throws Exception {
        this(new Builder(wireMock)
                .WithUserInfoServerUrl(userInfoServerUrl)
                        .WithEmailFieldName(emailFieldName)
                        .WithGroupsFieldName(groupsFieldName));
    }

    public TestRealm(WireMockExtension wireMock) throws Exception {
        this(new Builder(wireMock).WithMinimalDefaults());
    }

    public TestRealm(WireMockExtension wireMock, String userInfoServerUrl) throws Exception {
        this(new Builder(wireMock).WithMinimalDefaults().WithUserInfoServerUrl(userInfoServerUrl));
    }

    public TestRealm(
            WireMockExtension wireMock,
            String userInfoServerUrl,
            String emailFieldName,
            String groupFieldName,
            boolean automanualconfigure)
            throws Exception {
        this(new Builder(wireMock)
                .WithMinimalDefaults()
                        .WithUserInfoServerUrl(userInfoServerUrl)
                        .WithEmailFieldName(emailFieldName)
                        .WithGroupsFieldName(groupFieldName)
                        .WithAutomanualconfigure(automanualconfigure));
    }

    public TestRealm(
            WireMockExtension wireMock,
            String userInfoServerUrl,
            String emailFieldName,
            String groupFieldName,
            boolean automanualconfigure,
            boolean escapeHatchEnabled,
            String escapeHatchUsername,
            String escapeHatchSecret,
            String escapeHatchGroup)
            throws Exception {
        this(new Builder(wireMock)
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
    public void doFinishLogin(StaplerRequest2 request, StaplerResponse2 response) throws IOException, ParseException {
        /*
         * PluginTest uses a hardCoded nonce "nonce"
         */
        if (!isNonceDisabled()) {
            // only hack the nonce if the nonce is enabled
            FrameworkParameters parameters = new JEEFrameworkParameters(request, response);
            WebContext webContext = JEEContextFactory.INSTANCE.newContext(parameters);
            SessionStore sessionStore = JEESessionStoreFactory.INSTANCE.newSessionStore(parameters);
            OidcClient oidcClient = buildOidcClient();
            sessionStore.set(webContext, oidcClient.getNonceSessionAttributeName(), "nonce");
        }
        super.doFinishLogin(request, response);
    }

    public String getStringFieldFromJMESPath(Object object, String jmespathField) {
        Expression<Object> expr = compileJMESPath(jmespathField, "test field");
        if (expr == null) {
            return null;
        }
        return super.getStringField(object, expr);
    }

    @Serial
    @Override
    public Object readResolve() throws ObjectStreamException {
        return super.readResolve();
    }

    public boolean doCheckEscapeHatch(String username, String password) {
        return super.checkEscapeHatch(username, password);
    }
}

package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.lang.reflect.Field;

public class TestRealm extends OicSecurityRealm {

    public static final String CLIENT_ID = "clientId";
    public static final String EMAIL_FIELD = "email";
    public static final String FULL_NAME_FIELD = "fullName";
    public static final String GROUPS_FIELD = "groups";

    public static class Builder {
        public String clientId = CLIENT_ID;
        public String clientSecret = "secret";
        public String wellKnownOpenIDConfigurationUrl = null;
        public String tokenServerUrl;
        public String tokenAuthMethod = "client_secret_post";
        public String authorizationServerUrl;
        public String userInfoServerUrl = null;
        public String userNameField = null;
        public String tokenFieldToCheckKey = null;
        public String tokenFieldToCheckValue = null;
        public String fullNameFieldName= FULL_NAME_FIELD;
        public String emailFieldName = null;
        public String scopes = null;
        public String groupsFieldName = null;
        public boolean disableSslVerification = false;
        public Boolean logoutFromOpenidProvider = false;
        public String endSessionEndpoint = null;
        public String postLogoutRedirectUrl = null;
        public boolean escapeHatchEnabled = false;
        public String escapeHatchUsername = null;
        public String escapeHatchSecret = null;
        public String escapeHatchGroup = null;
        public String automanualconfigure = "manual";

            public Builder(WireMockRule wireMockRule) throws IOException {
             this.tokenServerUrl = "http://localhost:" + wireMockRule.port() + "/token";
             this.authorizationServerUrl = "http://localhost:" + wireMockRule.port() + "/authorization";
        }

        public Builder WithUserInfoServerUrl(String userInfoServerUrl) { this.userInfoServerUrl = userInfoServerUrl; return this; }
        public Builder WithEmailFieldName(String emailFieldName) { this.emailFieldName = emailFieldName; return this; }
        public Builder WithGroupsFieldName(String groupsFieldName) { this.groupsFieldName = groupsFieldName; return this; }
        public Builder WithPostLogoutRedirectUrl(String postLogoutRedirectUrl) { this.postLogoutRedirectUrl = postLogoutRedirectUrl; return this; }

        public Builder WithMinimalDefaults() { return this.WithEmailFieldName(EMAIL_FIELD).WithGroupsFieldName(GROUPS_FIELD); }
        public Builder WithLogout(Boolean logoutFromOpenidProvider, String endSessionEndpoint) {
            this.logoutFromOpenidProvider = logoutFromOpenidProvider;
            this.endSessionEndpoint = endSessionEndpoint;
            return this;
        }

        public TestRealm build() throws IOException {
            return new TestRealm(this);
        }
    };

    public TestRealm(Builder builder) throws IOException {
        super(
             builder.clientId,
             builder.clientSecret,
             builder.wellKnownOpenIDConfigurationUrl,
             builder.tokenServerUrl,
             builder.tokenAuthMethod,
             builder.authorizationServerUrl,
             builder.userInfoServerUrl,
             builder.userNameField,
             builder.tokenFieldToCheckKey,
             builder.tokenFieldToCheckValue,
             builder.fullNameFieldName,
             builder.emailFieldName,
             builder.scopes,
             builder.groupsFieldName,
             builder.disableSslVerification,
             builder.logoutFromOpenidProvider,
             builder.endSessionEndpoint,
             builder.postLogoutRedirectUrl,
             builder.escapeHatchEnabled,
             builder.escapeHatchUsername,
             builder.escapeHatchSecret,
             builder.escapeHatchGroup,
             builder.automanualconfigure
        );
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl, String emailFieldName, String groupsFieldName) throws IOException {
        this(new Builder(wireMockRule)
           .WithUserInfoServerUrl(userInfoServerUrl)
           .WithEmailFieldName(emailFieldName)
           .WithGroupsFieldName(groupsFieldName)
        );
    }

    public TestRealm(WireMockRule wireMockRule) throws IOException {
        this(new Builder(wireMockRule).WithMinimalDefaults());
    }

    public TestRealm(WireMockRule wireMockRule, String userInfoServerUrl) throws IOException {
        this(new Builder(wireMockRule).WithMinimalDefaults().WithUserInfoServerUrl(userInfoServerUrl));
    }

    @Override
    public HttpResponse doFinishLogin(StaplerRequest request) {
        try {
            Field field = OicSession.class.getDeclaredField("state");
            field.setAccessible(true);
            field.set(OicSession.getCurrent(), "state");
        } catch (Exception e) {
            throw new RuntimeException("can't fudge state",e);
        }
        return super.doFinishLogin(request);
    }

}

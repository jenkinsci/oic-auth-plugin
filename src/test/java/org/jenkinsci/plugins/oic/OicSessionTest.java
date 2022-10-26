package org.jenkinsci.plugins.oic;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpResponse;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;

import jenkins.model.Jenkins;

public class OicSessionTest {

    private OicSession session;

    private HttpTransport httpTransport;

    private static final String from = "fromAddy";

    private static final String token = "token";

    private final String tokenServerUrl = "http://localhost/token";

    private final String clientId = "myClientId";

    private final String clientSecret = "iunf82h709frj0se9ruf";

    private final String authorizationServerUrl = "http://localhost/auth";

    private final String scopes = "openid";

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Before
    public void init() {
        httpTransport = constructHttpTransport(true);

        final AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(BearerToken.queryParameterAccessMethod(),
            httpTransport, OicSecurityRealm.JSON_FACTORY, new GenericUrl(tokenServerUrl),
            new ClientParametersAuthentication(clientId, clientSecret), clientId, authorizationServerUrl)
                .setScopes(Arrays.asList(scopes)).build();

        session = new OicSession(flow, from, buildOAuthRedirectUrl()) {
            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                return null;
            }
        };
        session.setIdToken(token);
    }


    private String buildOAuthRedirectUrl() throws NullPointerException {
        String rootUrl = Jenkins.getInstance().getRootUrl();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }

    @Test
    public void getFrom() {
        assertEquals(from, session.getFrom());
    }

    @Test
    public void getIdToken() {
        assertEquals(token, session.getIdToken());
    }

    @Test
    public void getState() {
        assertNotEquals("", session.getState());
    }

    private static HttpTransport constructHttpTransport(boolean disableSslVerification) {
        NetHttpTransport.Builder builder = new NetHttpTransport.Builder();
        builder.setConnectionFactory(new JenkinsAwareConnectionFactory());

        if (disableSslVerification) {
            try {
                builder.doNotValidateCertificate();
            } catch (GeneralSecurityException ex) {
                // we do not handle this exception...
            }
        }

        return builder.build();
    }
}
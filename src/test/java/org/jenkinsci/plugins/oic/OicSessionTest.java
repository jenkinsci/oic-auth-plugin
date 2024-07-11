package org.jenkinsci.plugins.oic;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import java.io.IOException;
import jenkins.model.Jenkins;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class OicSessionTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    private OicSession session;

    private static final String from = "fromAddy";

    @Before
    public void init() throws IOException {
        TestRealm realm = new TestRealm.Builder("http://localhost/")
                .WithMinimalDefaults().WithScopes("openid").build();

        session = new OicSession(from, buildOAuthRedirectUrl()) {
            @Override
            public HttpResponse onSuccess(String authorizationCode, AuthorizationCodeFlow flow) {
                return null;
            }
        };
    }

    private String buildOAuthRedirectUrl() throws NullPointerException {
        String rootUrl = Jenkins.get().getRootUrl();
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
    public void getState() {
        assertNotEquals("", session.getState());
    }
}

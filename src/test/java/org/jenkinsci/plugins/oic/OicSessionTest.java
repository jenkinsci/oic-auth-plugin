package org.jenkinsci.plugins.oic;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import java.io.IOException;
import java.util.SortedMap;
import java.util.TreeMap;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OicSessionTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    private OicSession session;

    private static final String from = "fromAddy";

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
    public void getFrom() throws Exception {
        init();
        assertEquals(from, session.getFrom());
    }

    @Test
    public void getState() throws Exception {
        init();
        assertNotEquals("", session.getState());
    }

    @Test
    @WithoutJenkins
    public void testFormToQueryParameters() {
        StaplerRequest sr = mock(StaplerRequest.class);
        when(sr.getRequestURL())
                .thenReturn(new StringBuffer("http://domain.invalid/jenkins/securityRealm/finishLogin"));
        SortedMap<String, String[]> parametersMap = new TreeMap<>();
        parametersMap.put("param1", new String[] {"p1k1"});
        parametersMap.put("param2", new String[] {"p2k1", "p2k2"});
        when(sr.getParameterMap()).thenReturn(parametersMap);
        String converted = OicSession.convertFormToQueryParameters(sr);
        assertEquals(
                "http://domain.invalid/jenkins/securityRealm/finishLogin?param1=p1k1&param2=p2k1&param2=p2k2",
                converted);
    }
}

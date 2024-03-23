package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.util.FormValidation;
import java.io.IOException;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicSecurityRealm.DescriptorImpl;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.jenkinsci.plugins.oic.TestRealm.AUTO_CONFIG_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.MANUAL_CONFIG_FIELD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class DescriptorImplTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(), true);

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    private Jenkins jenkins;

    @Before
    public void setUp() {
        jenkins = jenkinsRule.getInstance();
    }

    @Test
    public void testOicSecurityRealmDescriptorImplManual() throws Exception {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, MANUAL_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();

        assertNotNull(descriptor);

        assertEquals("Login with Openid Connect", descriptor.getDisplayName());
        assertEquals("Client id is required.", descriptor.doCheckClientId(null).getMessage());
        assertEquals("Client id is required.", descriptor.doCheckClientId("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("goodClientId"));
        assertEquals("Client secret is required.", descriptor.doCheckClientSecret(null).getMessage());
        assertEquals("Client secret is required.", descriptor.doCheckClientSecret("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientSecret("password"));

        assertFalse(descriptor.isAuto());
        assertFalse(descriptor.isManual());

        jenkins.setSecurityRealm(realm);

        descriptor = (DescriptorImpl) realm.getDescriptor();

        assertNotNull(descriptor);

        assertFalse(descriptor.isAuto());
        assertTrue(descriptor.isManual());
    }

    @Test
    public void testOicSecurityRealmDescriptorImplAuto() throws Exception {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();

        assertNotNull(descriptor);

        assertEquals("Login with Openid Connect", descriptor.getDisplayName());
        assertEquals("Client id is required.", descriptor.doCheckClientId(null).getMessage());
        assertEquals("Client id is required.", descriptor.doCheckClientId("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("goodClientId"));
        assertEquals("Client secret is required.", descriptor.doCheckClientSecret(null).getMessage());
        assertEquals("Client secret is required.", descriptor.doCheckClientSecret("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientSecret("password"));

        jenkins.setSecurityRealm(realm);

        descriptor = (DescriptorImpl) realm.getDescriptor();

        assertNotNull(descriptor);

        assertTrue(descriptor.isAuto());
        assertFalse(descriptor.isManual());
    }

    @Test
    public void doCheckTokenServerUrl() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();

        assertNotNull(descriptor);
        assertEquals("Token Server Url Key is required.", descriptor.doCheckTokenServerUrl(null).getMessage());
        assertTrue(descriptor.doCheckTokenServerUrl("").getMessage().contains("is required."));
        assertEquals(FormValidation.ok(), descriptor.doCheckTokenServerUrl("http://localhost"));
    }

    @Test
    public void doCheckAuthorizationServerUrl() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();

        assertNotNull(descriptor);
        assertEquals("Token Server Url Key is required.", descriptor.doCheckAuthorizationServerUrl(null).getMessage());
        assertTrue(descriptor.doCheckAuthorizationServerUrl("").getMessage().contains("Not a valid url."));
        assertEquals(FormValidation.ok(), descriptor.doCheckAuthorizationServerUrl("http://localhost"));
    }

    @Test
    public void doCheckUserNameField() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals(FormValidation.ok("Using 'sub'.").getMessage(),
            descriptor.doCheckUserNameField(null).getMessage());
        assertEquals(FormValidation.ok("Using 'sub'.").getMessage(), descriptor.doCheckUserNameField("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckUserNameField("subfield"));
    }

    @Test
    public void doCheckFullNameFieldName() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals(FormValidation.ok(), descriptor.doCheckFullNameFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckFullNameFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckFullNameFieldName("myname"));
    }

    @Test
    public void doCheckEmailFieldName() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals(FormValidation.ok(), descriptor.doCheckEmailFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckEmailFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckEmailFieldName("myemail"));
    }

    @Test
    public void doCheckGroupsFieldName() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals(FormValidation.ok(), descriptor.doCheckGroupsFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckGroupsFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckGroupsFieldName("mygroups"));
    }

    @Test
    public void doCheckTokenFieldToCheckKey() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals(FormValidation.ok(), descriptor.doCheckTokenFieldToCheckKey(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckTokenFieldToCheckKey("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckTokenFieldToCheckKey("akey"));
    }

    @Test
    public void doCheckScopes() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals(FormValidation.ok("Using 'openid email'.").getMessage(),
            descriptor.doCheckScopes(null).getMessage());
        assertEquals(FormValidation.ok("Using 'openid email'.").getMessage(),
            descriptor.doCheckScopes("").getMessage());

        assertEquals(
            FormValidation.warning("Are you sure you don't want to include 'openid' as an scope?").getMessage(),
            descriptor.doCheckScopes("email username").getMessage());

        assertEquals(FormValidation.ok(), descriptor.doCheckScopes("openid"));
    }

    @Test
    public void doCheckEndSessionEndpoint() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals("End Session URL Key is required.",
            descriptor.doCheckEndSessionEndpoint(null).getMessage());
        assertEquals("End Session URL Key is required.",
            descriptor.doCheckEndSessionEndpoint("").getMessage());
        assertTrue(descriptor.doCheckEndSessionEndpoint("not a url").getMessage().contains("Not a valid url."));
        assertEquals(FormValidation.ok(), descriptor.doCheckEndSessionEndpoint("http://localhost"));
    }

    @Test
    public void doCheckPostLogoutRedirectUrl() throws IOException {
        configureWellKnown();
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, AUTO_CONFIG_FIELD);

        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertEquals(FormValidation.ok(), descriptor.doCheckPostLogoutRedirectUrl(null));
        assertEquals(FormValidation.ok(), descriptor.doCheckPostLogoutRedirectUrl(""));
        assertTrue(descriptor.doCheckPostLogoutRedirectUrl("not a url").getMessage().contains("Not a valid url."));
        assertEquals(FormValidation.ok(), descriptor.doCheckPostLogoutRedirectUrl("http://localhost"));
    }

    private void configureWellKnown() {
        String authUrl = "http://localhost:" + wireMockRule.port() + "/authorization";
        String tokenUrl = "http://localhost:" + wireMockRule.port() + "/token";
        String userInfoUrl = "http://localhost:" + wireMockRule.port() + "/userinfo";
        String jwksUrl = "null";
        String endSessionUrl = "null";

        wireMockRule.stubFor(get(urlPathEqualTo("/well.known")).willReturn(aResponse()
            .withHeader("Content-Type", "text/html; charset=utf-8")
            .withBody(String.format("{\"authorization_endpoint\": \"%s\", \"token_endpoint\":\"%s\", "
                + "\"userinfo_endpoint\":\"%s\",\"jwks_uri\":\"%s\", \"scopes_supported\": null, "
                + "\"end_session_endpoint\":\"%s\"}", authUrl, tokenUrl, userInfoUrl, jwksUrl, endSessionUrl))));
    }
}

package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import java.util.ArrayList;
import java.util.List;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicSecurityRealm.TokenAuthMethod;
import org.junit.Rule;
import org.junit.Test;

//import static io.jenkins.plugins.casc.misc.Util.*;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.jenkins.plugins.casc.misc.Util.getJenkinsRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class ConfigurationAsCodeTest {

    @Rule(order = 1)
    final public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();


    @Test
    @ConfiguredWithCode("ConfigurationAsCode.yml")
    public void testConfig() {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();

        assertTrue(realm instanceof OicSecurityRealm);
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;

        assertEquals("http://localhost", oicSecurityRealm.getAuthorizationServerUrl());
        assertEquals("clientId", oicSecurityRealm.getClientId());
        assertEquals("clientSecret", Secret.toString(oicSecurityRealm.getClientSecret()));
        assertTrue(oicSecurityRealm.isDisableSslVerification());
        assertEquals("emailFieldName", oicSecurityRealm.getEmailFieldName());
        assertTrue(oicSecurityRealm.isEscapeHatchEnabled());
        assertEquals("escapeHatchGroup", oicSecurityRealm.getEscapeHatchGroup());
        assertEquals("escapeHatchSecret", Secret.toString(oicSecurityRealm.getEscapeHatchSecret()));
        assertEquals("escapeHatchUsername", oicSecurityRealm.getEscapeHatchUsername());
        assertEquals("fullNameFieldName", oicSecurityRealm.getFullNameFieldName());
        assertEquals("groupsFieldName", oicSecurityRealm.getGroupsFieldName());
        assertTrue(oicSecurityRealm.isLogoutFromOpenidProvider());
        assertEquals("scopes", oicSecurityRealm.getScopes());
        assertEquals("http://localhost", oicSecurityRealm.getTokenServerUrl());
        assertEquals(TokenAuthMethod.client_secret_post, oicSecurityRealm.getTokenAuthMethod());
        assertEquals("userNameField", oicSecurityRealm.getUserNameField());
        assertTrue(oicSecurityRealm.isRootURLFromRequest());
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCode.yml")
    public void testExport() throws Exception {
        ConfigurationContext context = new ConfigurationContext(ConfiguratorRegistry.get());

        CNode yourAttribute = getJenkinsRoot(context).get("securityRealm").asMapping().get("oic");

        String exported = toYamlString(yourAttribute);

        // secrets are always changing. so, just remove them before there's a better solution
        String[] lines = exported.split("\n");
        List<String> lineList = new ArrayList<>();
        for (String line : lines) {
            if (!line.isEmpty() && !line.contains("Secret")) {
                lineList.add(line);
            }
        }
        String cleanedExported = String.join("\n", lineList);
        String expected = toStringFromYamlFile(this, "ConfigurationAsCodeExport.yml").trim();

        assertThat(cleanedExported, is(expected));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeMinimal.yml")
    public void testMinimal() throws Exception {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();

        assertTrue(realm instanceof OicSecurityRealm);
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;

        assertEquals("http://localhost/authorize", oicSecurityRealm.getAuthorizationServerUrl());
        assertEquals("clientId", oicSecurityRealm.getClientId());
        assertEquals("clientSecret", Secret.toString(oicSecurityRealm.getClientSecret()));
        assertFalse(oicSecurityRealm.isDisableSslVerification());
        assertNull(oicSecurityRealm.getEmailFieldName());
        assertFalse(oicSecurityRealm.isEscapeHatchEnabled());
        assertNull(oicSecurityRealm.getFullNameFieldName());
        assertNull(oicSecurityRealm.getGroupsFieldName());
        assertEquals("openid email", oicSecurityRealm.getScopes());
        assertEquals("http://localhost/token", oicSecurityRealm.getTokenServerUrl());
        assertEquals(TokenAuthMethod.client_secret_post, oicSecurityRealm.getTokenAuthMethod());
        assertEquals("sub", oicSecurityRealm.getUserNameField());
        assertTrue(oicSecurityRealm.isLogoutFromOpenidProvider());
        assertFalse(oicSecurityRealm.isRootURLFromRequest());
    }

    @Rule(order = 0)
    final public WellKnownMockRule wellKnownMockRule = new WellKnownMockRule("MOCK_PORT",
      "{\"authorization_endpoint\": \"http://localhost:%1$d/authorize\"," +
       "\"token_endpoint\":\"http://localhost:%1$d/token\"," +
       "\"userinfo_endpoint\":\"http://localhost:%1$d/user\","+
       "\"jwks_uri\":\"http://localhost:%1$d/authorize/jwks\"," +
       "\"scopes_supported\": null," +
       "\"end_session_endpoint\":\"http://localhost:%1$d/logout\"}");

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeMinimalWellKnown.yml")
    public void testMinimalWellKnown() throws Exception {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();

        assertTrue(realm instanceof OicSecurityRealm);
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;

        String urlBase = String.format("http://localhost:%d", wellKnownMockRule.port());

        assertEquals(urlBase+"/well.known", oicSecurityRealm.getWellKnownOpenIDConfigurationUrl());
        assertEquals(urlBase+"/authorize", oicSecurityRealm.getAuthorizationServerUrl());
        assertEquals(urlBase+"/token", oicSecurityRealm.getTokenServerUrl());
        assertEquals("clientId", oicSecurityRealm.getClientId());
        assertEquals("clientSecret", Secret.toString(oicSecurityRealm.getClientSecret()));
        assertFalse(oicSecurityRealm.isDisableSslVerification());
        assertNull(oicSecurityRealm.getEmailFieldName());
        assertFalse(oicSecurityRealm.isEscapeHatchEnabled());
        assertNull(oicSecurityRealm.getFullNameFieldName());
        assertNull(oicSecurityRealm.getGroupsFieldName());
        assertEquals("openid email", oicSecurityRealm.getScopes());
        assertEquals(urlBase+"/token", oicSecurityRealm.getTokenServerUrl());
        assertEquals(TokenAuthMethod.client_secret_post, oicSecurityRealm.getTokenAuthMethod());
        assertEquals("sub", oicSecurityRealm.getUserNameField());
        assertTrue(oicSecurityRealm.isLogoutFromOpenidProvider());
    }


    /** Class to setup WireMockRule for well known with stub and setting port in env variable
     */
    public class WellKnownMockRule extends  WireMockRule {
        private final String mockPortEnvName;
        private final String wellKnownAnswer;
        private String previousEnvValue;

        public WellKnownMockRule(String mockPortEnvName, String wellKnownAnswer) {
            super(new WireMockConfiguration().dynamicPort(), true);
            this.mockPortEnvName = mockPortEnvName;
            this.wellKnownAnswer = wellKnownAnswer;
        }

        @Override
        protected void before() {
            this.previousEnvValue = System.getProperty(this.mockPortEnvName);
            System.setProperty(this.mockPortEnvName, String.valueOf(port()));
            stubFor(get(urlPathEqualTo("/well.known")).willReturn(
                aResponse()
                    .withHeader("Content-Type", "text/html; charset=utf-8")
                    .withBody(String.format(this.wellKnownAnswer, port()))
            ));
            super.before();
        }

        @Override
        protected void after() {
            super.after();
            if(this.previousEnvValue != null) {
                System.setProperty(this.mockPortEnvName, this.previousEnvValue);
            } else {
                System.clearProperty(this.mockPortEnvName);
            }
        }
    }
}

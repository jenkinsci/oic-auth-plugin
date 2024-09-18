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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.jenkins.plugins.casc.misc.Util.getJenkinsRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class ConfigurationAsCodeTest {

    @Rule(order = 1)
    public final JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("ConfigurationAsCode.yml")
    public void testConfig() {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();

        assertTrue(realm instanceof OicSecurityRealm);
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;

        OicServerManualConfiguration serverConf =
                (OicServerManualConfiguration) oicSecurityRealm.getServerConfiguration();

        assertEquals("http://localhost/authorize", serverConf.getAuthorizationServerUrl());
        assertEquals("http://localhost/", serverConf.getIssuer());
        assertEquals("clientId", oicSecurityRealm.getClientId());
        assertEquals("clientSecret", Secret.toString(oicSecurityRealm.getClientSecret()));
        assertTrue(oicSecurityRealm.isDisableSslVerification());
        assertEquals("emailFieldName", oicSecurityRealm.getEmailFieldName());
        assertTrue(oicSecurityRealm.isEscapeHatchEnabled());
        assertEquals("escapeHatchGroup", oicSecurityRealm.getEscapeHatchGroup());
        assertEquals(
                "$2a$10$fxteEkfDqwqkmUelZmTxlu9WESjVDKQhp6jsqB1AgsLQ2dC6jikga",
                Secret.toString(oicSecurityRealm.getEscapeHatchSecret()));
        assertEquals("escapeHatchUsername", oicSecurityRealm.getEscapeHatchUsername());
        assertEquals("fullNameFieldName", oicSecurityRealm.getFullNameFieldName());
        assertEquals("groupsFieldName", oicSecurityRealm.getGroupsFieldName());
        assertTrue(oicSecurityRealm.isLogoutFromOpenidProvider());
        assertEquals("scopes", serverConf.getScopes());
        assertEquals("http://localhost/token", serverConf.getTokenServerUrl());
        assertEquals(TokenAuthMethod.client_secret_post, serverConf.getTokenAuthMethod());
        assertEquals("userNameField", oicSecurityRealm.getUserNameField());
        assertTrue(oicSecurityRealm.isRootURLFromRequest());
        assertEquals("http://localhost/jwks", serverConf.getJwksServerUrl());
        assertFalse(oicSecurityRealm.isDisableTokenVerification());
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCode.yml")
    public void testExport() throws Exception {
        ConfigurationContext context = new ConfigurationContext(ConfiguratorRegistry.get());

        CNode yourAttribute =
                getJenkinsRoot(context).get("securityRealm").asMapping().get("oic");

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
        String expected =
                toStringFromYamlFile(this, "ConfigurationAsCodeExport.yml").trim();

        assertThat(cleanedExported, is(expected));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeMinimal.yml")
    public void testMinimal() throws Exception {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();

        assertTrue(realm instanceof OicSecurityRealm);
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;
        OicServerManualConfiguration serverConf =
                (OicServerManualConfiguration) oicSecurityRealm.getServerConfiguration();

        assertEquals("http://localhost/authorize", serverConf.getAuthorizationServerUrl());
        assertEquals("http://localhost/", serverConf.getIssuer());
        assertEquals("clientId", oicSecurityRealm.getClientId());
        assertEquals("clientSecret", Secret.toString(oicSecurityRealm.getClientSecret()));
        assertFalse(oicSecurityRealm.isDisableSslVerification());
        assertNull(oicSecurityRealm.getEmailFieldName());
        assertFalse(oicSecurityRealm.isEscapeHatchEnabled());
        assertNull(oicSecurityRealm.getFullNameFieldName());
        assertNull(oicSecurityRealm.getGroupsFieldName());
        assertEquals("openid email", serverConf.getScopes());
        assertEquals("http://localhost/token", serverConf.getTokenServerUrl());
        assertEquals(TokenAuthMethod.client_secret_post, serverConf.getTokenAuthMethod());
        assertEquals("sub", oicSecurityRealm.getUserNameField());
        assertTrue(oicSecurityRealm.isLogoutFromOpenidProvider());
        assertFalse(oicSecurityRealm.isRootURLFromRequest());
        assertEquals(null, serverConf.getJwksServerUrl());
        assertFalse(oicSecurityRealm.isDisableTokenVerification());
    }

    @Rule(order = 0)
    public final WellKnownMockRule wellKnownMockRule = new WellKnownMockRule(
            "MOCK_PORT",
            "{\"issuer\": \"http://localhost:%1$d/\","
                    + "\"authorization_endpoint\": \"http://localhost:%1$d/authorize\","
                    + "\"token_endpoint\":\"http://localhost:%1$d/token\","
                    + "\"userinfo_endpoint\":\"http://localhost:%1$d/user\","
                    + "\"jwks_uri\":\"http://localhost:%1$d/jwks\","
                    + "\"scopes_supported\": [\"openid\",\"email\"],"
                    + "\"subject_types_supported\": [\"public\"],"
                    + "\"end_session_endpoint\":\"http://localhost:%1$d/logout\"}");

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeMinimalWellKnown.yml")
    public void testMinimalWellKnown() throws Exception {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        assertThat(realm, instanceOf(OicSecurityRealm.class));
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;

        assertThat(oicSecurityRealm.getServerConfiguration(), instanceOf(OicServerWellKnownConfiguration.class));
        OicServerWellKnownConfiguration serverConf =
                (OicServerWellKnownConfiguration) oicSecurityRealm.getServerConfiguration();

        String urlBase = String.format("http://localhost:%d", wellKnownMockRule.port());

        assertFalse(oicSecurityRealm.isDisableSslVerification());
        assertNull(oicSecurityRealm.getEmailFieldName());
        assertFalse(oicSecurityRealm.isEscapeHatchEnabled());
        assertNull(oicSecurityRealm.getFullNameFieldName());
        assertNull(oicSecurityRealm.getGroupsFieldName());

        assertEquals("clientId", oicSecurityRealm.getClientId());
        assertEquals("clientSecret", Secret.toString(oicSecurityRealm.getClientSecret()));

        assertEquals("sub", oicSecurityRealm.getUserNameField());
        assertTrue(oicSecurityRealm.isLogoutFromOpenidProvider());
        assertFalse(oicSecurityRealm.isDisableTokenVerification());

        assertEquals(urlBase + "/well.known", serverConf.getWellKnownOpenIDConfigurationUrl());
    }

    /** Class to setup WireMockRule for well known with stub and setting port in env variable
     */
    public class WellKnownMockRule extends WireMockRule {
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
            stubFor(get(urlPathEqualTo("/well.known"))
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "text/html; charset=utf-8")
                            .withBody(String.format(this.wellKnownAnswer, port()))));
            super.before();
        }

        @Override
        protected void after() {
            super.after();
            if (this.previousEnvValue != null) {
                System.setProperty(this.mockPortEnvName, this.previousEnvValue);
            } else {
                System.clearProperty(this.mockPortEnvName);
            }
        }
    }
}

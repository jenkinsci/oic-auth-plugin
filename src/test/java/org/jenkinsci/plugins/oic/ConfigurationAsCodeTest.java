package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import io.jenkins.plugins.casc.model.CNode;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicSecurityRealm.TokenAuthMethod;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static io.jenkins.plugins.casc.misc.Util.getJenkinsRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkinsConfiguredWithCode
class ConfigurationAsCodeTest {

    @RegisterExtension
    static WellKnownMockExtension wellKnownMockExtension = new WellKnownMockExtension(
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
    @ConfiguredWithCode("ConfigurationAsCode.yml")
    void testConfig(JenkinsConfiguredWithCodeRule j) {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();

        assertInstanceOf(OicSecurityRealm.class, realm);
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
        assertNotNull(oicSecurityRealm.getLoginQueryParamNameValuePairs());
        assertNotNull(oicSecurityRealm.getLogoutQueryParamNameValuePairs());
        assertEquals(
                "loginkey1x\"xx@me=loginvalue1xxxx@you&?loginneu&/test==login?sunny%&/xx\"x",
                oicSecurityRealm.getLoginQueryParamNameValuePairs().stream()
                        .map(config -> config.getQueryParamName() + "=" + config.getQueryParamValue())
                        .collect(Collectors.joining("&")));
        assertEquals(
                "logoutkey1x\"xx@me=logoutvalue1xxxx@you&?logoutneu&/test==logout?sunny%&/xx\"x",
                oicSecurityRealm.getLogoutQueryParamNameValuePairs().stream()
                        .map(config -> config.getQueryParamName() + "=" + config.getQueryParamValue())
                        .collect(Collectors.joining("&")));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCode.yml")
    void testExport(JenkinsConfiguredWithCodeRule j) throws Exception {
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
    void testMinimal(JenkinsConfiguredWithCodeRule j) {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();

        assertInstanceOf(OicSecurityRealm.class, realm);
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
        assertNull(serverConf.getJwksServerUrl());
        assertFalse(oicSecurityRealm.isDisableTokenVerification());
        assertNull(oicSecurityRealm.getLoginQueryParamNameValuePairs());
        assertNull(oicSecurityRealm.getLogoutQueryParamNameValuePairs());
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeMinimalWellKnown.yml")
    void testMinimalWellKnown(JenkinsConfiguredWithCodeRule j) {
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        assertThat(realm, instanceOf(OicSecurityRealm.class));
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) realm;

        assertThat(oicSecurityRealm.getServerConfiguration(), instanceOf(OicServerWellKnownConfiguration.class));
        OicServerWellKnownConfiguration serverConf =
                (OicServerWellKnownConfiguration) oicSecurityRealm.getServerConfiguration();

        String urlBase = String.format("http://localhost:%d", wellKnownMockExtension.getPort());

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

        assertNull(oicSecurityRealm.getLoginQueryParamNameValuePairs());
        assertNull(oicSecurityRealm.getLogoutQueryParamNameValuePairs());
    }

    /** Class to setup WellKnownMockExtension for well known with stub and setting port in env variable
     */
    public static class WellKnownMockExtension extends WireMockExtension {
        private final String mockPortEnvName;
        private final String wellKnownAnswer;
        private String previousEnvValue;

        public WellKnownMockExtension(String mockPortEnvName, String wellKnownAnswer) {
            super(WireMockExtension.newInstance()
                    .failOnUnmatchedRequests(true)
                    .options(wireMockConfig().dynamicPort()));
            this.mockPortEnvName = mockPortEnvName;
            this.wellKnownAnswer = wellKnownAnswer;
        }

        @Override
        protected void onBeforeAll(ExtensionContext context, WireMockRuntimeInfo info) {
            this.previousEnvValue = System.getProperty(this.mockPortEnvName);
            System.setProperty(this.mockPortEnvName, String.valueOf(getPort()));
            stubFor(get(urlPathEqualTo("/well.known"))
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "text/html; charset=utf-8")
                            .withBody(String.format(this.wellKnownAnswer, getPort()))));
        }

        @Override
        protected void onAfterAll(ExtensionContext context, WireMockRuntimeInfo info) {
            if (this.previousEnvValue != null) {
                System.setProperty(this.mockPortEnvName, this.previousEnvValue);
            } else {
                System.clearProperty(this.mockPortEnvName);
            }
        }
    }
}

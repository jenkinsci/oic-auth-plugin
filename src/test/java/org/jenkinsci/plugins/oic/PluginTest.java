package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertAnonymous;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestAvatar;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUserEmail;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUserIsMemberOfGroups;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUserIsMemberOfTestGroups;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_ENCODED_AVATAR;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_EMAIL_ADDRESS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_FULL_NAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_GROUPS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_GROUPS_MAP;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.belongsToGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.browseLoginPage;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureTestRealm;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureWellKnown;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.createKeyPair;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.encodePublicKey;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.getAuthentication;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.setUpKeyValuesNested;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.setUpKeyValuesNoGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.setUpKeyValuesWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.setUpKeyValuesWithGroupAndSub;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.toJson;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.toUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdToken;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithValues;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithoutValues;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfo;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoJwtWithTestGroups;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithAvatar;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithGroups;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithTestGroups;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.google.gson.JsonNull;
import com.nimbusds.oauth2.sdk.Scope;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.VersionNumber;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLException;
import jenkins.model.Jenkins;
import jenkins.security.LastGrantedAuthoritiesProperty;
import org.htmlunit.CookieManager;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.Cookie;
import org.jenkinsci.plugins.oic.plugintest.PluginTestHelper;
import org.jenkinsci.plugins.oic.properties.DisableNonce;
import org.jenkinsci.plugins.oic.properties.DisableTokenVerification;
import org.jenkinsci.plugins.oic.properties.Pkce;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.Url;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.Stapler;
import org.springframework.security.core.Authentication;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
@Url("https://jenkins.io/blog/2018/01/13/jep-200/")
@WithJenkins
class PluginTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort().dynamicHttpsPort())
            .build();

    private JenkinsRule jenkinsRule;
    private JenkinsRule.WebClient webClient;
    private Jenkins jenkins;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        this.jenkinsRule = jenkinsRule;
        jenkins = jenkinsRule.getInstance();
        webClient = jenkinsRule.createWebClient();
    }

    @Test
    void testLoginWithDefaults() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, sc -> {});
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);

        wireMock.verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("scope", equalTo("openid email"))
                .withQueryParam("nonce", matching(".+")));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(notMatching(".*&scope=.*")));
        webClient.executeOnServer(() -> {
            Stapler.getCurrentRequest2().getSession();
            assertNotNull(((OicSecurityRealm) Jenkins.get().getSecurityRealm()).getStateAttribute());
            return null;
        });
    }

    @Test
    void testLoginWithDefaultsUntrustedTLSFails() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        TestRealm.Builder builder = new TestRealm.Builder(wireMock, true).WithMinimalDefaults();
        jenkins.setSecurityRealm(builder.build());
        assertThrows(SSLException.class, () -> browseLoginPage(webClient, jenkins));
    }

    @Test
    void testLoginWithDefaultsUntrustedTLSPassesWhenTLSChecksDisabled() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        TestRealm.Builder builder =
                new TestRealm.Builder(wireMock, true).WithMinimalDefaults().WithDisableSslVerification(true);
        jenkins.setSecurityRealm(builder.build());
        // webclient talks to the OP via SSL so we need to disable Webclients TLS validation also
        webClient.getOptions().setUseInsecureSSL(true);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    @Issue("SECURITY-3473")
    void testSessionRefresh() throws Exception {
        String cookieName = "JSESSIONID";
        String cookieHost = jenkinsRule.getURL().getHost();
        // Dev memo: jenkinsRule.getURL().getPath() has a trailing / which breaks Cookie#equals
        String cookiePath = jenkinsRule.contextPath;
        String previousSession = "fakesessionid0123456789";
        CookieManager cookieManager = webClient.getCookieManager();
        Cookie jSessionIDCookie = new Cookie(cookieHost, cookieName, previousSession, cookiePath, null, false, true);

        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, sc -> {});

        // Not yet logged in
        assertAnonymous(webClient);
        assertEquals(
                0,
                cookieManager.getCookies().stream()
                        .filter(c -> Objects.equals(c.getName(), cookieName))
                        .count(),
                "No session cookie should be present");

        // Set a JSESSIONID cookie value before the first login is attempted.
        cookieManager.addCookie(jSessionIDCookie);

        browseLoginPage(webClient, jenkins);

        // Multiple JSESSIONID can exist if, for example, the path is different
        assertEquals(
                1,
                cookieManager.getCookies().stream()
                        .filter(c -> Objects.equals(c.getName(), cookieName))
                        .count(),
                "Only one session cookie should be present");

        String firstLoginSession = cookieManager.getCookie(cookieName).getValue();
        assertNotEquals(previousSession, firstLoginSession, "The previous session should be replaced with a new one");

        browseLoginPage(webClient, jenkins);

        String secondLoginSession = cookieManager.getCookie(cookieName).getValue();
        assertNotEquals(firstLoginSession, secondLoginSession, "The session should be renewed when the user log in");
    }

    @Test
    @Disabled("there is no configuration option for this and the spec does not have scopes in a token endpoint")
    void testLoginWithScopesInTokenRequest() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, sc -> sc.setSendScopesInTokenRequest(true));
        browseLoginPage(webClient, jenkins);

        wireMock.verify(
                getRequestedFor(urlPathEqualTo("/authorization")).withQueryParam("scope", equalTo("openid email")));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("&scope=openid+email&")));
    }

    @Test
    void testLoginWithPkceEnabled() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);

        configureTestRealm(wireMock, jenkins, sc -> sc.getProperties().add(new Pkce()));
        browseLoginPage(webClient, jenkins);

        wireMock.verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("code_challenge_method", equalTo("S256"))
                .withQueryParam("code_challenge", matching(".+")));
        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(matching(".*&code_verifier=[^&]+.*")));

        // check PKCE
        // - get codeChallenge
        final String codeChallenge = wireMock.findAll(getRequestedFor(urlPathEqualTo("/authorization")))
                .get(0)
                .queryParameter("code_challenge")
                .values()
                .get(0);
        // - get verifierCode
        Matcher m = Pattern.compile(".*&code_verifier=([^&]+).*")
                .matcher(wireMock.findAll(postRequestedFor(urlPathEqualTo("/token")))
                        .get(0)
                        .getBodyAsString());
        assertTrue(m.find());
        final String codeVerifier = m.group(1);

        // - hash verifierCode
        byte[] bytes = codeVerifier.getBytes();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes, 0, bytes.length);
        byte[] digest = md.digest();
        final String verifyChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

        assertEquals(verifyChallenge, codeChallenge);
    }

    @Test
    void testLoginWithNonceDisabled() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, sc -> sc.getProperties().add(new DisableNonce()));
        browseLoginPage(webClient, jenkins);

        wireMock.verify(getRequestedFor(urlPathEqualTo("/authorization")).withQueryParam("nonce", absent()));
    }

    @Test
    void testLoginUsingUserInfoEndpointWithGroupsMap() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithGroups(wireMock, TEST_USER_GROUPS_MAP);

        System.out.println("jsonarray : " + toJson(TEST_USER_GROUPS_MAP));
        jenkins.setSecurityRealm(new TestRealm(
                wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo", "email", "groups[].name"));
        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        for (Map<String, String> group : TEST_USER_GROUPS_MAP) {
            var groupName = group.get("name");
            assertTrue(user.getAuthorities().contains(groupName), "User should be part of group " + groupName);
        }
    }

    @Test
    void testLoginUsingUserInfoEndpointWithAvatar() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithAvatar(wireMock);
        configureWellKnown(wireMock, null, null);

        // Return avatar image when requested
        wireMock.stubFor(get(urlPathEqualTo("/my-avatar.png"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "image/png")
                        .withBody(Base64.getDecoder().decode(TEST_ENCODED_AVATAR))));

        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous(webClient);
        assertTestAvatar(null, wireMock);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestAvatar(user, wireMock);
    }

    @Test
    void testLoginWithMinimalConfiguration() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, null, null));
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);

        var user = assertTestUser(webClient);
        assertTrue(user.getAuthorities().isEmpty(), "User should be not be part of any group");
    }

    @Test
    void testLoginWithAutoConfiguration() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        configureWellKnown(wireMock, null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    public void testLoginWithCustomLoginParameters() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        configureWellKnown(wireMock, null, null);
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithAutomanualconfigure(true)
                        .WithLoginQueryParameters(
                                List.of(new LoginQueryParameter("queryLoginParamName", "queryLoginParamValue")))
                        .build());
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    void testLoginWithAutoConfiguration_WithNoScope() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithValues(wireMock, setUpKeyValuesNoGroup());
        mockUserInfoWithGroups(wireMock, null);
        configureWellKnown(wireMock, null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous(webClient);
        configureWellKnown(wireMock, null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertThat("User should be not be part of any group", user.getAuthorities(), empty());
    }

    @Test
    void testConfigurationWithAutoConfiguration_withScopeOverride() throws Exception {
        configureWellKnown(wireMock, null, List.of("openid", "profile", "scope1", "scope2", "scope3"));
        TestRealm oicsr = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults().WithAutomanualconfigure(true).build();
        jenkins.setSecurityRealm(oicsr);
        assertEquals(
                new Scope("openid", "profile", "scope1", "scope2", "scope3"),
                oicsr.getServerConfiguration().toProviderMetadata().getScopes(),
                "All scopes of WellKnown should be used");
        OicServerWellKnownConfiguration serverConfig = (OicServerWellKnownConfiguration) oicsr.getServerConfiguration();

        serverConfig.setScopesOverride("openid profile scope2 other");
        serverConfig.invalidateProviderMetadata(); // XXX should not be used as it is not a normal code flow, rather the
        // code should create a new ServerConfig
        assertEquals(
                new Scope("openid", "profile", "scope2", "other"),
                serverConfig.toProviderMetadata().getScopes(),
                "scopes should be completely overridden");

        serverConfig.invalidateProviderMetadata(); // XXX should not be used as it is not a normal code flow, rather the
        // code should create a new ServerConfig
        serverConfig.setScopesOverride("");
        assertEquals(
                new Scope("openid", "profile", "scope1", "scope2", "scope3"),
                serverConfig.toProviderMetadata().getScopes(),
                "All scopes of WellKnown should be used");
    }

    @Test
    void testTokenExpiration_withoutExpiresInValue() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        jenkins.setSecurityRealm(testRealm);
        // login
        mockTokenReturnsIdTokenWithGroup(wireMock, PluginTestHelper::withoutExpiresIn);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        OicCredentials credentials = user.getProperty(OicCredentials.class);

        assertNotNull(credentials);
        assertNull(credentials.getExpiresAtMillis());
    }

    @Test
    void testreadResolve_withNulls() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithValues(wireMock, setUpKeyValuesWithGroup());
        mockUserInfoWithTestGroups(wireMock);

        configureWellKnown(wireMock, null, null);

        TestRealm realm = new TestRealm(wireMock, null, null, null, true);
        jenkins.setSecurityRealm(realm);

        assertEquals(realm, realm.readResolve());
    }

    @Test
    void testreadResolve_withNonNulls() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        configureWellKnown(wireMock, "http://localhost/endSession", null);
        TestRealm realm = new TestRealm(wireMock, null, null, null, true);
        jenkins.setSecurityRealm(realm);
        assertEquals(realm, realm.readResolve());
    }

    @Test
    void testLoginUsingUserInfoEndpoint() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    void testLoginUsingUserInfoWithJWT() throws Exception {
        KeyPair keyPair = createKeyPair();
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoJwtWithTestGroups(wireMock, keyPair, "group1");

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfGroups(user, "group1");
    }

    @Test
    void testLoginWithJWTSignature() throws Exception {
        KeyPair keyPair = createKeyPair();

        wireMock.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\":[{" + encodePublicKey(keyPair) + ",\"use\":\"sig\",\"kid\":\"jwks_key_id\""
                                + "}]}")));
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock, keyPair);
        mockUserInfoJwtWithTestGroups(wireMock, keyPair, TEST_USER_GROUPS);

        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithUserInfoServerUrl("http://localhost:" + wireMock.getPort() + "/userinfo")
                        .WithJwksServerUrl("http://localhost:" + wireMock.getPort() + "/jwks")
                        .WithDisableTokenValidation(false)
                        .build());

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        Authentication authentication = getAuthentication(webClient);
        assertEquals(TEST_USER_USERNAME, authentication.getPrincipal(), "Should be logged-in as " + TEST_USER_USERNAME);
    }

    @Test
    @Disabled("never enabled, fails because of https://github.com/jenkinsci/oic-auth-plugin/pull/308")
    void testLoginWithWrongJWTSignature() throws Exception {
        KeyPair keyPair = createKeyPair();

        wireMock.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\":[{" + encodePublicKey(keyPair)
                                + ",\"use\":\"sig\",\"kid\":\"wrong_key_id\"" + "}]}")));
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock, keyPair);
        mockUserInfoJwtWithTestGroups(wireMock, keyPair, TEST_USER_GROUPS);
        TestRealm testRealm = new TestRealm.Builder(wireMock)
                .WithUserInfoServerUrl("http://localhost:" + wireMock.getPort() + "/userinfo")
                        .WithJwksServerUrl("http://localhost:" + wireMock.getPort() + "/jwks")
                        .build();
        jenkins.setSecurityRealm(testRealm);
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        assertAnonymous(webClient);
        testRealm.getProperties().add(new DisableTokenVerification());
        browseLoginPage(webClient, jenkins);
        Authentication authentication = getAuthentication(webClient);
        assertEquals(TEST_USER_USERNAME, authentication.getPrincipal(), "Should be logged-in as " + TEST_USER_USERNAME);
    }

    @Test
    void testShouldLogUserWithoutGroupsWhenUserGroupIsMissing() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithGroups(wireMock, null);

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        User user = toUser(getAuthentication(webClient));
        assertNotNull(user);
        assertTrue(user.getAuthorities().isEmpty(), "User shouldn't be part of any group");
    }

    @Test
    void testShouldLogUserWithoutGroupsWhenUserGroupIsNull() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithGroups(wireMock, JsonNull.INSTANCE);

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        Authentication authentication = getAuthentication(webClient);
        User user = toUser(authentication);
        assertNotNull(user);
        assertTrue(user.getAuthorities().isEmpty(), "User shouldn't be part of any group");
    }

    @Test
    void testShouldLogUserWithoutGroupsWhenUserGroupIsNotAStringList() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithGroups(wireMock, Map.of("not", "a group"));

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        User user = toUser(getAuthentication(webClient));
        assertNotNull(user);
        assertTrue(user.getAuthorities().isEmpty(), "User shouldn't be part of any group");
    }

    @Test
    void testNestedFieldLookup() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithValues(wireMock, setUpKeyValuesNested());
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, "nested.email", "nested.groups"));
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    void testNestedFieldLookupFromUserInfoEndpoint() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfo(
                wireMock,
                Map.of(
                        "sub",
                        TEST_USER_USERNAME,
                        FULL_NAME_FIELD,
                        TEST_USER_FULL_NAME,
                        "nested",
                        Map.of("email", TEST_USER_EMAIL_ADDRESS, "groups", TEST_USER_GROUPS),
                        EMAIL_FIELD,
                        ""));

        jenkins.setSecurityRealm(new TestRealm(
                wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo", "nested.email", "nested.groups"));

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    void testFieldLookupFromIdTokenWhenNotInUserInfoEndpoint() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);

        mockTokenReturnsIdTokenWithValues(wireMock, setUpKeyValuesWithGroupAndSub());
        mockUserInfo(wireMock, Map.of("sub", "", FULL_NAME_FIELD, JsonNull.INSTANCE, GROUPS_FIELD, TEST_USER_GROUPS));

        jenkins.setSecurityRealm(
                new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo", "email", "groups"));
        browseLoginPage(webClient, jenkins);

        Authentication authentication = getAuthentication(webClient);
        assertEquals(
                TEST_USER_USERNAME,
                authentication.getPrincipal(),
                "Should read field (ex:username) from IdToken when empty in userInfo");
        User user = toUser(authentication);
        assertNotNull(user);
        assertEquals(
                TEST_USER_FULL_NAME,
                user.getFullName(),
                "Should read field (ex:full name) from IdToken when null in userInfo");
        assertEquals(
                TEST_USER_EMAIL_ADDRESS,
                user.getProperty(Mailer.UserProperty.class).getAddress(),
                "Should read field (ex:email) from IdToken when not in userInfo");
    }

    @Test
    void testGroupListFromStringInfoEndpoint() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfo(
                wireMock,
                Map.of(
                        "sub",
                        TEST_USER_USERNAME,
                        FULL_NAME_FIELD,
                        TEST_USER_FULL_NAME,
                        "nested",
                        Map.of(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS, GROUPS_FIELD, TEST_USER_GROUPS)));

        jenkins.setSecurityRealm(new TestRealm(
                wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo", "nested.email", "nested.groups"));

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        var user = assertTestUser(webClient);
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
        assertEquals(2, user.getAuthorities().size(), "User should be in 2 groups");
    }

    @Test
    void testLastGrantedAuthoritiesProperty() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);

        mockTokenReturnsIdTokenWithValues(wireMock, setUpKeyValuesWithGroup());

        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, false));

        assertAnonymous(webClient);

        browseLoginPage(webClient, jenkins);

        var user = assertTestUser(webClient);

        assertTestUserEmail(user);
        assertEquals(2, user.getAuthorities().size(), "User should be in 2 groups");

        LastGrantedAuthoritiesProperty userProperty = user.getProperty(LastGrantedAuthoritiesProperty.class);
        assertEquals(
                3, userProperty.getAuthorities2().size(), "Property should specify 3 groups (2 + 'authenticated')");

        VersionNumber version = Jenkins.getVersion();
        assertNotNull(version);
        HtmlPage configure = version.isNewerThan(new VersionNumber("2.467"))
                ? webClient.goTo("me/account/")
                : webClient.goTo("me/configure");
        jenkinsRule.submit(configure.getFormByName("config"));
        user = User.getById(TEST_USER_USERNAME, false);
        assertNotNull(user);
        assertEquals(2, user.getAuthorities().size(), "User should still be in 2 groups");
        userProperty = user.getProperty(LastGrantedAuthoritiesProperty.class);
        assertEquals(
                3,
                userProperty.getAuthorities2().size(),
                "Property should still specify 3 groups (2 + 'authenticated')");
    }

    @Test
    void testLogoutShouldBeJenkinsOnlyWhenNoProviderLogoutConfigured() throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMock).build();
        jenkins.setSecurityRealm(oicsr);

        String[] logoutURL = new String[1];
        jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest2(), Jenkins.ANONYMOUS2);
            return null;
        });
        assertEquals("/jenkins/", logoutURL[0]);
    }

    @Test
    void testLogoutShouldBeProviderURLWhenProviderLogoutConfigured() throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMock)
                .WithLogout(Boolean.TRUE, "http://provider/logout").build();
        jenkins.setSecurityRealm(oicsr);

        String[] logoutURL = new String[1];
        jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest2(), Jenkins.ANONYMOUS2);
            return null;
        });
        assertEquals("http://provider/logout", logoutURL[0]);
    }

    @Test
    public void testLogoutShouldBeProviderURLWhenProviderLogoutConfiguredWithAdditionalLogoutQueryParameters()
            throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMock)
                .WithLogoutQueryParameters(List.of(
                                new LogoutQueryParameter("hello", "world"), new LogoutQueryParameter("single", "")))
                        .WithLogout(Boolean.TRUE, "http://provider/logout")
                        .build();
        jenkins.setSecurityRealm(oicsr);

        String[] logoutURL = new String[1];
        jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest2(), Jenkins.ANONYMOUS2);
            return null;
        });
        assertEquals("http://provider/logout?hello=world&single", logoutURL[0]);
    }

    @Test
    void testLogoutShouldBeProviderURLWithRedirectWhenProviderLogoutConfiguredWithPostlogoutRedirect()
            throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMock)
                .WithLogout(Boolean.TRUE, "http://provider/logout")
                        .WithPostLogoutRedirectUrl("http://see.it/?cat&color=white")
                        .build();
        jenkins.setSecurityRealm(oicsr);

        String[] logoutURL = new String[1];
        jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest2(), Jenkins.ANONYMOUS2);
            return null;
        });
        assertEquals(
                "http://provider/logout?post_logout_redirect_uri=http%3A%2F%2Fsee.it%2F%3Fcat%26color%3Dwhite",
                logoutURL[0]);
    }

    @Test
    void testLoginWithMissingIdTokenShouldBeRefused() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdToken(wireMock, null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, null, null));
        assertAnonymous(webClient);
        webClient.assertFails(jenkins.getSecurityRealm().getLoginUrl(), 500);
    }

    @Test
    void testLoginWithUnreadableIdTokenShouldBeRefused() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdToken(wireMock, "This is not an IdToken");
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, null, null));
        assertAnonymous(webClient);
        webClient.assertFails(jenkins.getSecurityRealm().getLoginUrl(), 500);
    }

    @Test
    void loginWithCheckTokenSuccess() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, belongsToGroup("group1"));
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);
    }

    @Test
    void loginWithCheckTokenFailure() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        configureTestRealm(wireMock, jenkins, belongsToGroup("missing-group"));
        assertAnonymous(webClient);
        webClient.setThrowExceptionOnFailingStatusCode(false);
        browseLoginPage(webClient, jenkins);
        assertAnonymous(webClient);
    }

    @Test
    @Issue("SECURITY-3441")
    void loginWithIncorrectIssuerFails() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithIssuer("another_issuer").WithDisableTokenValidation(false).build());
        assertAnonymous(webClient);
        webClient.setThrowExceptionOnFailingStatusCode(false);
        browseLoginPage(webClient, jenkins);
        assertAnonymous(webClient);
    }

    @Test
    @Issue("SECURITY-3441")
    void loginWithIncorrectAudienceFails() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithGroup(wireMock);
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithClient("another_client_id", "client_secret")
                        .WithDisableTokenValidation(false)
                        .build());
        assertAnonymous(webClient);
        webClient.setThrowExceptionOnFailingStatusCode(false);
        browseLoginPage(webClient, jenkins);
        assertAnonymous(webClient);
    }
}

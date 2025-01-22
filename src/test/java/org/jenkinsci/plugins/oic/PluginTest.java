package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.gson.JsonNull;
import com.nimbusds.oauth2.sdk.Scope;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.VersionNumber;
import jakarta.servlet.http.HttpSession;
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
import org.jenkinsci.plugins.oic.plugintest.Mocks;
import org.jenkinsci.plugins.oic.plugintest.TestHelper;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.Url;
import org.kohsuke.stapler.Stapler;
import org.springframework.security.core.Authentication;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.findAll;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
@Url("https://jenkins.io/blog/2018/01/13/jep-200/")
public class PluginTest {

    private static final List<Map<String, String>> TEST_USER_GROUPS_MAP =
            List.of(Map.of("id", "id1", "name", "group1"), Map.of("id", "id2", "name", "group2"));

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(
            new WireMockConfiguration()
                    .dynamicPort()
                    .dynamicHttpsPort()
                    .notifier(new ConsoleNotifier(new DisableOnDebug(null).isDebugging())),
            true);

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    private JenkinsRule.WebClient webClient;
    private Jenkins jenkins;

    @Before
    public void setUp() {
        jenkins = jenkinsRule.getInstance();
        webClient = jenkinsRule.createWebClient();
        if (new DisableOnDebug(null).isDebugging()) {
            webClient.getOptions().setTimeout(0);
        }
    }

    @Test
    public void testLoginWithDefaults() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestHelper.configureTestRealm(wireMockRule, jenkins, sc -> {});
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfTestGroups(user);

        verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("scope", equalTo("openid email"))
                .withQueryParam("nonce", matching(".+")));
        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(notMatching(".*&scope=.*")));
        webClient.executeOnServer(() -> {
            HttpSession session = Stapler.getCurrentRequest2().getSession();
            assertNotNull(((OicSecurityRealm) Jenkins.get().getSecurityRealm()).getStateAttribute(session));
            return null;
        });
    }

    @Test
    public void testLoginWithDefaultsUntrustedTLSFails() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestRealm.Builder builder = new TestRealm.Builder(wireMockRule, true).WithMinimalDefaults();
        jenkins.setSecurityRealm(builder.build());
        assertThrows(SSLException.class, () -> TestHelper.browseLoginPage(webClient, jenkins));
    }

    @Test
    public void testLoginWithDefaultsUntrustedTLSPassesWhenTLSChecksDisabled() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestRealm.Builder builder =
                new TestRealm.Builder(wireMockRule, true).WithMinimalDefaults().WithDisableSslVerification(true);
        jenkins.setSecurityRealm(builder.build());
        // webclient talks to the OP via SSL so we need to disable Webclients TLS validation also
        webClient.getOptions().setUseInsecureSSL(true);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    @Issue("SECURITY-3473")
    public void testSessionRefresh() throws Exception {
        String cookieName = "JSESSIONID";
        String cookieHost = jenkinsRule.getURL().getHost();
        // Dev memo: jenkinsRule.getURL().getPath() has a trailing / which breaks Cookie#equals
        String cookiePath = jenkinsRule.contextPath;
        String previousSession = "fakesessionid0123456789";
        CookieManager cookieManager = webClient.getCookieManager();
        Cookie jSessionIDCookie = new Cookie(cookieHost, cookieName, previousSession, cookiePath, null, false, true);

        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestHelper.configureTestRealm(wireMockRule, jenkins, sc -> {});

        // Not yet logged in
        TestHelper.assertAnonymous(webClient);
        assertEquals(
                "No session cookie should be present",
                0,
                cookieManager.getCookies().stream()
                        .filter(c -> Objects.equals(c.getName(), cookieName))
                        .count());

        // Set a JSESSIONID cookie value before the first login is attempted.
        cookieManager.addCookie(jSessionIDCookie);

        TestHelper.browseLoginPage(webClient, jenkins);

        // Multiple JSESSIONID can exist if, for example, the path is different
        assertEquals(
                "Only one session cookie should be present",
                1,
                cookieManager.getCookies().stream()
                        .filter(c -> Objects.equals(c.getName(), cookieName))
                        .count());

        String firstLoginSession = cookieManager.getCookie(cookieName).getValue();
        assertNotEquals("The previous session should be replaced with a new one", previousSession, firstLoginSession);

        TestHelper.browseLoginPage(webClient, jenkins);

        String secondLoginSession = cookieManager.getCookie(cookieName).getValue();
        assertNotEquals("The session should be renewed when the user log in", firstLoginSession, secondLoginSession);
    }

    @Test
    @Ignore("there is no configuration option for this and the spec does not have scopes in a token endpoint")
    public void testLoginWithScopesInTokenRequest() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestHelper.configureTestRealm(wireMockRule, jenkins, sc -> sc.setSendScopesInTokenRequest(true));
        TestHelper.browseLoginPage(webClient, jenkins);

        verify(getRequestedFor(urlPathEqualTo("/authorization")).withQueryParam("scope", equalTo("openid email")));
        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("&scope=openid+email&")));
    }

    @Test
    public void testLoginWithPkceEnabled() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);

        TestHelper.configureTestRealm(wireMockRule, jenkins, sc -> sc.setPkceEnabled(true));
        TestHelper.browseLoginPage(webClient, jenkins);

        verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("code_challenge_method", equalTo("S256"))
                .withQueryParam("code_challenge", matching(".+")));
        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(matching(".*&code_verifier=[^&]+.*")));

        // check PKCE
        // - get codeChallenge
        final String codeChallenge = findAll(getRequestedFor(urlPathEqualTo("/authorization")))
                .get(0)
                .queryParameter("code_challenge")
                .values()
                .get(0);
        // - get verifierCode
        Matcher m = Pattern.compile(".*&code_verifier=([^&]+).*")
                .matcher(findAll(postRequestedFor(urlPathEqualTo("/token")))
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
    public void testLoginWithNonceDisabled() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestHelper.configureTestRealm(wireMockRule, jenkins, sc -> sc.setNonceDisabled(true));
        TestHelper.browseLoginPage(webClient, jenkins);

        verify(getRequestedFor(urlPathEqualTo("/authorization")).withQueryParam("nonce", absent()));
    }

    @Test
    public void testLoginUsingUserInfoEndpointWithGroupsMap() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfoWithGroups(wireMockRule, TEST_USER_GROUPS_MAP);

        System.out.println("jsonarray : " + TestHelper.toJson(TEST_USER_GROUPS_MAP));
        jenkins.setSecurityRealm(new TestRealm(
                wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo", "email", "groups[].name"));
        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        for (Map<String, String> group : TEST_USER_GROUPS_MAP) {
            var groupName = group.get("name");
            assertTrue(
                    "User should be part of group " + groupName,
                    user.getAuthorities().contains(groupName));
        }
    }

    @Test
    public void testLoginWithMinimalConfiguration() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, null, null));
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);

        var user = TestHelper.assertTestUser(webClient);
        assertTrue(
                "User should be not be part of any group", user.getAuthorities().isEmpty());
    }

    @Test
    public void testLoginWithAutoConfiguration() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.configureWellKnown(wireMockRule, null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true));
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    public void testLoginWithAutoConfiguration_WithNoScope() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithValues(wireMockRule, TestHelper.setUpKeyValuesNoGroup());
        Mocks.mockUserInfoWithGroups(wireMockRule, null);
        TestHelper.configureWellKnown(wireMockRule, null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true));
        TestHelper.assertAnonymous(webClient);
        TestHelper.configureWellKnown(wireMockRule, null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true));
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        assertThat("User should be not be part of any group", user.getAuthorities(), empty());
    }

    @Test
    public void testConfigurationWithAutoConfiguration_withScopeOverride() throws Exception {
        TestHelper.configureWellKnown(wireMockRule, null, List.of("openid", "profile", "scope1", "scope2", "scope3"));
        TestRealm oicsr = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults().WithAutomanualconfigure(true).build();
        jenkins.setSecurityRealm(oicsr);
        assertEquals(
                "All scopes of WellKnown should be used",
                new Scope("openid", "profile", "scope1", "scope2", "scope3"),
                oicsr.getServerConfiguration().toProviderMetadata().getScopes());
        OicServerWellKnownConfiguration serverConfig = (OicServerWellKnownConfiguration) oicsr.getServerConfiguration();

        serverConfig.setScopesOverride("openid profile scope2 other");
        serverConfig.invalidateProviderMetadata(); // XXX should not be used as it is not a normal code flow, rather the
        // code should create a new ServerConfig
        assertEquals(
                "scopes should be completely overridden",
                new Scope("openid", "profile", "scope2", "other"),
                serverConfig.toProviderMetadata().getScopes());

        serverConfig.invalidateProviderMetadata(); // XXX should not be used as it is not a normal code flow, rather the
        // code should create a new ServerConfig
        serverConfig.setScopesOverride("");
        assertEquals(
                "All scopes of WellKnown should be used",
                new Scope("openid", "profile", "scope1", "scope2", "scope3"),
                serverConfig.toProviderMetadata().getScopes());
    }

    @Test
    public void testTokenExpiration_withoutExpiresInValue() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true);
        jenkins.setSecurityRealm(testRealm);
        // login
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule, TestHelper::withoutExpiresIn);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        OicCredentials credentials = user.getProperty(OicCredentials.class);

        assertNotNull(credentials);
        assertNull(credentials.getExpiresAtMillis());
    }

    @Test
    public void testReadResolve_withNulls() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithValues(wireMockRule, TestHelper.setUpKeyValuesWithGroup());
        Mocks.mockUserInfoWithTestGroups(wireMockRule);

        TestHelper.configureWellKnown(wireMockRule, null, null);

        TestRealm realm = new TestRealm(wireMockRule, null, null, null, true);
        jenkins.setSecurityRealm(realm);

        assertEquals(realm, realm.readResolve());
    }

    @Test
    public void testReadResolve_withNonNulls() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.configureWellKnown(wireMockRule, "http://localhost/endSession", null);
        TestRealm realm = new TestRealm(wireMockRule, null, null, null, true);
        jenkins.setSecurityRealm(realm);
        assertEquals(realm, realm.readResolve());
    }

    @Test
    public void testLoginUsingUserInfoEndpoint() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    public void testLoginUsingUserInfoWithJWT() throws Exception {
        KeyPair keyPair = TestHelper.createKeyPair();
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfoJwtWithTestGroups(wireMockRule, keyPair, "group1");

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfGroups(user, "group1");
    }

    @Test
    public void testLoginWithJWTSignature() throws Exception {
        KeyPair keyPair = TestHelper.createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\":[{" + TestHelper.encodePublicKey(keyPair)
                                + ",\"use\":\"sig\",\"kid\":\"jwks_key_id\"" + "}]}")));
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule, keyPair);
        Mocks.mockUserInfoJwtWithTestGroups(wireMockRule, keyPair, TestHelper.TEST_USER_GROUPS);

        jenkins.setSecurityRealm(new TestRealm.Builder(wireMockRule)
                .WithUserInfoServerUrl("http://localhost:" + wireMockRule.port() + "/userinfo")
                        .WithJwksServerUrl("http://localhost:" + wireMockRule.port() + "/jwks")
                        .WithDisableTokenValidation(false)
                        .build());

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        Object principal = TestHelper.getPrincipal(webClient);
        assertEquals(
                "Should be logged-in as " + TestHelper.TEST_USER_USERNAME, TestHelper.TEST_USER_USERNAME, principal);
    }

    @Test
    @Ignore("never enabled, fails because of https://github.com/jenkinsci/oic-auth-plugin/pull/308")
    public void testLoginWithWrongJWTSignature() throws Exception {
        KeyPair keyPair = TestHelper.createKeyPair();

        wireMockRule.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\":[{" + TestHelper.encodePublicKey(keyPair)
                                + ",\"use\":\"sig\",\"kid\":\"wrong_key_id\"" + "}]}")));
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule, keyPair);
        Mocks.mockUserInfoJwtWithTestGroups(wireMockRule, keyPair, TestHelper.TEST_USER_GROUPS);
        TestRealm testRealm = new TestRealm.Builder(wireMockRule)
                .WithUserInfoServerUrl("http://localhost:" + wireMockRule.port() + "/userinfo")
                        .WithJwksServerUrl("http://localhost:" + wireMockRule.port() + "/jwks")
                        .build();
        jenkins.setSecurityRealm(testRealm);
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertAnonymous(webClient);
        testRealm.setDisableTokenVerification(true);
        TestHelper.browseLoginPage(webClient, jenkins);
        Object principal = TestHelper.getPrincipal(webClient);
        assertEquals(
                "Should be logged-in as " + TestHelper.TEST_USER_USERNAME, TestHelper.TEST_USER_USERNAME, principal);
    }

    @Test
    public void testShouldLogUserWithoutGroupsWhenUserGroupIsMissing() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfoWithGroups(wireMockRule, null);

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        Authentication authentication = TestHelper.getAuthentication(webClient);
        assertNotNull("Authentication should not be null", authentication);
        User user = TestHelper.toUser(authentication);
        assertNotNull("User should not be null", user);
        assertTrue("User shouldn't be part of any group", user.getAuthorities().isEmpty());
    }

    @Test
    public void testShouldLogUserWithoutGroupsWhenUserGroupIsNull() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfoWithGroups(wireMockRule, JsonNull.INSTANCE);

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        Authentication authentication = TestHelper.getAuthentication(webClient);
        assertNotNull("Authentication should not be null", authentication);
        User user = TestHelper.toUser(authentication);
        assertNotNull("User should not be null", user);
        assertTrue("User shouldn't be part of any group", user.getAuthorities().isEmpty());
    }

    @Test
    public void testShouldLogUserWithoutGroupsWhenUserGroupIsNotAStringList() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfoWithGroups(wireMockRule, Map.of("not", "a group"));

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo"));

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        Authentication authentication = TestHelper.getAuthentication(webClient);
        assertNotNull("Authentication should not be null", authentication);
        User user = TestHelper.toUser(authentication);
        assertNotNull("User should not be null", user);
        assertTrue("User shouldn't be part of any group", user.getAuthorities().isEmpty());
    }

    @Test
    public void testNestedFieldLookup() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithValues(wireMockRule, TestHelper.setUpKeyValuesNested());
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, "nested.email", "nested.groups"));
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    public void testNestedFieldLookupFromUserInfoEndpoint() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfo(
                wireMockRule,
                Map.of(
                        "sub",
                        TestHelper.TEST_USER_USERNAME,
                        FULL_NAME_FIELD,
                        TestHelper.TEST_USER_FULL_NAME,
                        "nested",
                        Map.of("email", TestHelper.TEST_USER_EMAIL_ADDRESS, "groups", TestHelper.TEST_USER_GROUPS),
                        EMAIL_FIELD,
                        ""));

        jenkins.setSecurityRealm(new TestRealm(
                wireMockRule,
                "http://localhost:" + wireMockRule.port() + "/userinfo",
                "nested.email",
                "nested.groups"));

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    public void testFieldLookupFromIdTokenWhenNotInUserInfoEndpoint() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);

        Mocks.mockTokenReturnsIdTokenWithValues(wireMockRule, TestHelper.setUpKeyValuesWithGroupAndSub());
        Mocks.mockUserInfo(
                wireMockRule,
                Map.of("sub", "", FULL_NAME_FIELD, JsonNull.INSTANCE, GROUPS_FIELD, TestHelper.TEST_USER_GROUPS));

        jenkins.setSecurityRealm(new TestRealm(
                wireMockRule, "http://localhost:" + wireMockRule.port() + "/userinfo", "email", "groups"));
        TestHelper.browseLoginPage(webClient, jenkins);

        assertEquals(
                "Should read field (ex:username) from IdToken when empty in userInfo",
                TestHelper.TEST_USER_USERNAME,
                TestHelper.getPrincipal(webClient));

        Authentication authentication = TestHelper.getAuthentication(webClient);
        assertNotNull("Authentication should not be null", authentication);
        User user = TestHelper.toUser(authentication);
        assertNotNull("User should not be null", user);
        assertEquals(
                "Should read field (ex:full name) from IdToken when null in userInfo",
                TestHelper.TEST_USER_FULL_NAME,
                user.getFullName());
        assertEquals(
                "Should read field (ex:email) from IdToken when not in userInfo",
                TestHelper.TEST_USER_EMAIL_ADDRESS,
                user.getProperty(Mailer.UserProperty.class).getAddress());
    }

    @Test
    public void testGroupListFromStringInfoEndpoint() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfo(
                wireMockRule,
                Map.of(
                        "sub",
                        TestHelper.TEST_USER_USERNAME,
                        FULL_NAME_FIELD,
                        TestHelper.TEST_USER_FULL_NAME,
                        "nested",
                        Map.of(
                                EMAIL_FIELD,
                                TestHelper.TEST_USER_EMAIL_ADDRESS,
                                GROUPS_FIELD,
                                TestHelper.TEST_USER_GROUPS)));

        jenkins.setSecurityRealm(new TestRealm(
                wireMockRule,
                "http://localhost:" + wireMockRule.port() + "/userinfo",
                "nested.email",
                "nested.groups"));

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        var user = TestHelper.assertTestUser(webClient);
        TestHelper.assertTestUserEmail(user);
        TestHelper.assertTestUserIsMemberOfTestGroups(user);
        assertEquals("User should be in 2 groups", 2, user.getAuthorities().size());
    }

    @Test
    public void testLastGrantedAuthoritiesProperty() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);

        Mocks.mockTokenReturnsIdTokenWithValues(wireMockRule, TestHelper.setUpKeyValuesWithGroup());

        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, false));

        TestHelper.assertAnonymous(webClient);

        TestHelper.browseLoginPage(webClient, jenkins);

        var user = TestHelper.assertTestUser(webClient);

        TestHelper.assertTestUserEmail(user);
        assertEquals("User should be in 2 groups", 2, user.getAuthorities().size());

        LastGrantedAuthoritiesProperty userProperty = user.getProperty(LastGrantedAuthoritiesProperty.class);
        assertEquals(
                "Property should specify 3 groups (2 + 'authenticated')",
                3,
                userProperty.getAuthorities2().size());

        VersionNumber version = Jenkins.getVersion();
        assertNotNull("Jenkins version must not be null", version);
        HtmlPage configure = version.isNewerThan(new VersionNumber("2.467"))
                ? webClient.goTo("me/account/")
                : webClient.goTo("me/configure");
        jenkinsRule.submit(configure.getFormByName("config"));
        user = User.getById(TestHelper.TEST_USER_USERNAME, false);
        assertNotNull("User should not be null", user);
        assertEquals(
                "User should still be in 2 groups", 2, user.getAuthorities().size());
        userProperty = user.getProperty(LastGrantedAuthoritiesProperty.class);
        assertEquals(
                "Property should still specify 3 groups (2 + 'authenticated')",
                3,
                userProperty.getAuthorities2().size());
    }

    @Test
    public void testLogoutShouldBeJenkinsOnlyWhenNoProviderLogoutConfigured() throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMockRule).build();
        jenkins.setSecurityRealm(oicsr);

        String[] logoutURL = new String[1];
        jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest2(), Jenkins.ANONYMOUS2);
            return null;
        });
        assertEquals("/jenkins/", logoutURL[0]);
    }

    @Test
    public void testLogoutShouldBeProviderURLWhenProviderLogoutConfigured() throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMockRule)
                .WithLogout(Boolean.TRUE, "http://provider/logout").build();
        jenkins.setSecurityRealm(oicsr);

        String[] logoutURL = new String[1];
        jenkinsRule.executeOnServer(() -> {
            logoutURL[0] = oicsr.getPostLogOutUrl2(Stapler.getCurrentRequest2(), Jenkins.ANONYMOUS2);
            return null;
        });
        assertEquals("http://provider/logout?state=null", logoutURL[0]);
    }

    @Test
    public void testLogoutShouldBeProviderURLWithRedirectWhenProviderLogoutConfiguredWithPostlogoutRedirect()
            throws Exception {
        final TestRealm oicsr = new TestRealm.Builder(wireMockRule)
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
                "http://provider/logout?state=null&post_logout_redirect_uri=http%3A%2F%2Fsee.it%2F%3Fcat%26color%3Dwhite",
                logoutURL[0]);
    }

    @Test
    public void testLoginWithMissingIdTokenShouldBeRefused() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdToken(wireMockRule, null);
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, null, null));
        TestHelper.assertAnonymous(webClient);
        webClient.assertFails(jenkins.getSecurityRealm().getLoginUrl(), 500);
    }

    @Test
    public void testLoginWithUnreadableIdTokenShouldBeRefused() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdToken(wireMockRule, "This is not an IdToken");
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, null, null));
        TestHelper.assertAnonymous(webClient);
        webClient.assertFails(jenkins.getSecurityRealm().getLoginUrl(), 500);
    }

    @Test
    public void loginWithCheckTokenSuccess() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestHelper.configureTestRealm(wireMockRule, jenkins, TestHelper.belongsToGroup("group1"));
        TestHelper.assertAnonymous(webClient);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertTestUser(webClient);
    }

    @Test
    public void loginWithCheckTokenFailure() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        TestHelper.configureTestRealm(wireMockRule, jenkins, TestHelper.belongsToGroup("missing-group"));
        TestHelper.assertAnonymous(webClient);
        webClient.setThrowExceptionOnFailingStatusCode(false);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertAnonymous(webClient);
    }

    @Test
    @Issue("SECURITY-3441")
    public void loginWithIncorrectIssuerFails() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMockRule)
                .WithIssuer("another_issuer").WithDisableTokenValidation(false).build());
        TestHelper.assertAnonymous(webClient);
        webClient.setThrowExceptionOnFailingStatusCode(false);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertAnonymous(webClient);
    }

    @Test
    @Issue("SECURITY-3441")
    public void loginWithIncorrectAudienceFails() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMockRule)
                .WithClient("another_client_id", "client_secret")
                        .WithDisableTokenValidation(false)
                        .build());
        TestHelper.assertAnonymous(webClient);
        webClient.setThrowExceptionOnFailingStatusCode(false);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertAnonymous(webClient);
    }
}

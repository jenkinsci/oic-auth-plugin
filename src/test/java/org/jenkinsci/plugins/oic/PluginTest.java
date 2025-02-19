package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.util.VersionNumber;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLException;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import jenkins.security.LastGrantedAuthoritiesProperty;
import org.htmlunit.CookieManager;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.Cookie;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.xml.sax.SAXException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.google.gson.JsonParser.parseString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
@Url("https://jenkins.io/blog/2018/01/13/jep-200/")
@WithJenkins
class PluginTest {
    private static final String TEST_USER_USERNAME = "testUser";
    private static final String TEST_USER_EMAIL_ADDRESS = "test@jenkins.oic";
    private static final String TEST_USER_FULL_NAME = "Oic Test User";
    private static final String[] TEST_USER_GROUPS = new String[] {"group1", "group2"};
    private static final String[] TEST_USER_GROUPS_REFRESHED = new String[] {"group1", "group2", "group3"};
    private static final List<Map<String, String>> TEST_USER_GROUPS_MAP =
            List.of(Map.of("id", "id1", "name", "group1"), Map.of("id", "id2", "name", "group2"));
    private static final String TEST_ENCODED_AVATAR =
            "iVBORw0KGgoAAAANSUhEUgAAABsAAAAaCAYAAABGiCfwAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAH8SURBVEhL7ZbPK0RRFMe/z/w05Mc0Mo0mZeFXGM1IFDFEfjWKks1sSIkipDSrt1M2FpY2FpSllK2yV/4DWYlSLGzw7rvufe/Rm5n3a4rJwmdz77nz3vnee865Z56QSCQoikSJNhaFvy823Ulwsf6BWFTWVpxRsFionGJ7TEZtBSCmCEoE5ykvWGxtmMDvUefRIDDf/UtibXUUEx3ZzpcHCSpKNcOGgsQyk0QZbx/ecHDxhOdXCQEvsJpU1+1wLDYVk9FYq54qc/yAtcN7HF0+K/ZMnKChxj6cjsT8Hop1lqsvPojq+F1SR0EQsDMuKXMrHIkt9smoLtMME+L1wFCL9VWwFQtXUqR7nd2nzRECt0szDLAV2xq1dqAnXAmke8yLxVIsXk+RbLZPvJ7Ffh5y43dMxVjOHSU9F37h9cWkx1RsNi6zctaMHLxuthPdmMtUjLJrkp9nVyQSEbX5NwEvxf68BJ/H2Flr1I9wtRtLI0GU+oz32xQGzm6yfzN8ciUpsxZkLMTxs01UlbmUUJvBW9t4e/bp8sSiQYq5LutSF08flQ5ycvWirRjDc8cbwhd5YdydIUo3t6KpzgeJdZGNVMg0jJyAD5CZ1vWd+kzWNwg/+tFC4RVoxTtzN7DnYS0uR4z/VYgpCeVsRz/FPYu0eO5W5v9fVz9CEcWAT+xkgmHqzLIIAAAAAElFTkSuQmCC";

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
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        configureTestRealm(sc -> {});
        assertAnonymous();
        browseLoginPage();
        var user = assertTestUser();
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);

        wireMock.verify(getRequestedFor(urlPathEqualTo("/authorization"))
                .withQueryParam("scope", equalTo("openid email"))
                .withQueryParam("nonce", matching(".+")));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(notMatching(".*&scope=.*")));
        webClient.executeOnServer(() -> {
            HttpSession session = Stapler.getCurrentRequest2().getSession();
            assertNotNull(((OicSecurityRealm) Jenkins.get().getSecurityRealm()).getStateAttribute(session));
            return null;
        });
    }

    @Test
    void testLoginWithDefaultsUntrustedTLSFails() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        TestRealm.Builder builder = new TestRealm.Builder(wireMock, true).WithMinimalDefaults();
        jenkins.setSecurityRealm(builder.build());
        assertThrows(SSLException.class, this::browseLoginPage);
    }

    @Test
    void testLoginWithDefaultsUntrustedTLSPassesWhenTLSChecksDisabled() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        TestRealm.Builder builder =
                new TestRealm.Builder(wireMock, true).WithMinimalDefaults().WithDisableSslVerification(true);
        jenkins.setSecurityRealm(builder.build());
        // webclient talks to the OP via SSL so we need to disable Webclients TLS validation also
        webClient.getOptions().setUseInsecureSSL(true);
        browseLoginPage();
        var user = assertTestUser();
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

        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        configureTestRealm(sc -> {});

        // Not yet logged in
        assertAnonymous();
        assertEquals(
                0,
                cookieManager.getCookies().stream()
                        .filter(c -> Objects.equals(c.getName(), cookieName))
                        .count(),
                "No session cookie should be present");

        // Set a JSESSIONID cookie value before the first login is attempted.
        cookieManager.addCookie(jSessionIDCookie);

        browseLoginPage();

        // Multiple JSESSIONID can exist if, for example, the path is different
        assertEquals(
                1,
                cookieManager.getCookies().stream()
                        .filter(c -> Objects.equals(c.getName(), cookieName))
                        .count(),
                "Only one session cookie should be present");

        String firstLoginSession = cookieManager.getCookie(cookieName).getValue();
        assertNotEquals(previousSession, firstLoginSession, "The previous session should be replaced with a new one");

        browseLoginPage();

        String secondLoginSession = cookieManager.getCookie(cookieName).getValue();
        assertNotEquals(firstLoginSession, secondLoginSession, "The session should be renewed when the user log in");
    }

    private void browseLoginPage() throws IOException, SAXException {
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());
    }

    private void configureTestRealm(@NonNull Consumer<OicSecurityRealm> consumer) throws Exception {
        var securityRealm = new TestRealm(wireMock);
        consumer.accept(securityRealm);
        jenkins.setSecurityRealm(securityRealm);
    }

    private static void assertTestUserIsMemberOfTestGroups(User user) {
        assertTestUserIsMemberOfGroups(user, TEST_USER_GROUPS);
    }

    private static void assertTestUserIsMemberOfGroups(User user, String... testUserGroups) {
        for (String group : testUserGroups) {
            assertTrue(user.getAuthorities().contains(group), "User should be part of group " + group);
        }
    }

    private void assertAnonymous() {
        assertEquals(
                Jenkins.ANONYMOUS2.getPrincipal(), getAuthentication().getPrincipal(), "Shouldn't be authenticated");
    }

    private void mockAuthorizationRedirectsToFinishLogin() {
        wireMock.stubFor(get(urlPathEqualTo("/authorization"))
                .willReturn(aResponse()
                        .withTransformers("response-template")
                        .withStatus(302)
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withHeader(
                                "Location",
                                jenkins.getRootUrl()
                                        + "securityRealm/finishLogin?state={{request.query.state}}&code=code")));
    }

    @Test
    @Disabled("there is no configuration option for this and the spec does not have scopes in a token endpoint")
    void testLoginWithScopesInTokenRequest() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        configureTestRealm(sc -> sc.setSendScopesInTokenRequest(true));
        browseLoginPage();

        wireMock.verify(
                getRequestedFor(urlPathEqualTo("/authorization")).withQueryParam("scope", equalTo("openid email")));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("&scope=openid+email&")));
    }

    @Test
    void testLoginWithPkceEnabled() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();

        configureTestRealm(sc -> sc.setPkceEnabled(true));
        browseLoginPage();

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
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        configureTestRealm(sc -> sc.setNonceDisabled(true));
        browseLoginPage();

        wireMock.verify(getRequestedFor(urlPathEqualTo("/authorization")).withQueryParam("nonce", absent()));
    }

    @Test
    void testLoginUsingUserInfoEndpointWithGroupsMap() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoWithGroups(TEST_USER_GROUPS_MAP);

        System.out.println("jsonarray : " + toJson(TEST_USER_GROUPS_MAP));
        jenkins.setSecurityRealm(new TestRealm(
                wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo", "email", "groups[].name"));
        assertAnonymous();

        browseLoginPage();

        var user = assertTestUser();
        assertTestUserEmail(user);
        for (Map<String, String> group : TEST_USER_GROUPS_MAP) {
            var groupName = group.get("name");
            assertTrue(user.getAuthorities().contains(groupName), "User should be part of group " + groupName);
        }
    }

    @Test
    void testLoginUsingUserInfoEndpointWithAvatar() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoWithAvatar(wireMock);
        configureWellKnown(null, null);

        // Return avatar image when requested
        wireMock.stubFor(get(urlPathEqualTo("/my-avatar.png"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "image/png")
                        .withBody(Base64.getDecoder().decode(TEST_ENCODED_AVATAR))));

        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous();
        browseLoginPage();
        var user = assertTestUser();
        assertTestUserEmail(user);
        assertTestAvatar(user, wireMock);
    }

    @Test
    void testLoginWithMinimalConfiguration() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, null, null));
        assertAnonymous();
        browseLoginPage();

        var user = assertTestUser();
        assertTrue(user.getAuthorities().isEmpty(), "User should be not be part of any group");
    }

    @Test
    void testLoginWithAutoConfiguration() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        mockUserInfoWithTestGroups();
        configureWellKnown(null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous();
        browseLoginPage();
        var user = assertTestUser();
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    void testLoginWithAutoConfiguration_WithNoScope() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithValues(setUpKeyValuesNoGroup());
        mockUserInfoWithGroups(null);
        configureWellKnown(null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous();
        configureWellKnown(null, null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        assertAnonymous();
        browseLoginPage();
        var user = assertTestUser();
        assertTestUserEmail(user);
        assertThat("User should be not be part of any group", user.getAuthorities(), empty());
    }

    @Test
    void testConfigurationWithAutoConfiguration_withScopeOverride() throws Exception {
        configureWellKnown(null, List.of("openid", "profile", "scope1", "scope2", "scope3"));
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
    void testConfigurationWithAutoConfiguration_withRefreshToken() throws Exception {
        configureWellKnown(null, null, "authorization_code", "refresh_token");
        TestRealm oicsr = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults().WithAutomanualconfigure(true).build();
        jenkins.setSecurityRealm(oicsr);
        assertTrue(
                oicsr.getServerConfiguration()
                        .toProviderMetadata()
                        .getGrantTypes()
                        .contains(GrantType.REFRESH_TOKEN),
                "Refresh token should be enabled");
    }

    @Test
    void testRefreshToken_validAndExtendedToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        configureWellKnown(null, null, "authorization_code", "refresh_token");
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        // user groups on first login
        mockTokenReturnsIdTokenWithGroup();
        mockUserInfoWithTestGroups();
        browseLoginPage();
        var user = assertTestUser();
        assertFalse(
                user.getAuthorities().contains(TEST_USER_GROUPS_REFRESHED[2]),
                "User should not be part of group " + TEST_USER_GROUPS_REFRESHED[2]);

        // refresh user with different groups
        mockTokenReturnsIdTokenWithValues(setUpKeyValuesWithGroup(TEST_USER_GROUPS_REFRESHED));
        mockUserInfoWithGroups(TEST_USER_GROUPS_REFRESHED);
        expire();
        webClient.goTo(jenkins.getSearchUrl());

        user = assertTestUser();
        assertTrue(
                user.getAuthorities().contains(TEST_USER_GROUPS_REFRESHED[2]),
                "User should be part of group " + TEST_USER_GROUPS_REFRESHED[2]);

        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
    }

    private HttpResponse<String> getPageWithGet(String url) throws IOException, InterruptedException {
        // fix up the url, if needed
        if (url.startsWith("/")) {
            url = url.substring(1);
        }

        HttpClient c = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        return c.send(
                HttpRequest.newBuilder(URI.create(jenkinsRule.getURL() + url))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /**
     * performs a GET request using a basic authorization header
     * @param user - The user id
     * @param token - the password api token to user
     * @param url - the url to request
     * @return HttpResponse
     * @throws IOException
     * @throws InterruptedException
     */
    private HttpResponse<String> getPageWithGet(String user, String token, String url)
            throws IOException, InterruptedException {
        // fix up the url, if needed
        if (url.startsWith("/")) {
            url = url.substring(1);
        }

        HttpClient c = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
        return c.send(
                HttpRequest.newBuilder(URI.create(jenkinsRule.getURL() + url))
                        .header(
                                "Authorization",
                                "Basic "
                                        + Base64.getEncoder()
                                                .encodeToString((user + ":" + token).getBytes(StandardCharsets.UTF_8)))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void testRefreshTokenAndTokenExpiration_withoutRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        configureWellKnown(null, null, "authorization_code");
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        // login
        mockTokenReturnsIdTokenWithGroup(PluginTest::withoutRefreshToken);
        mockUserInfoWithTestGroups();
        browseLoginPage();
        assertTestUser();
        // expired token not refreshed
        expire();
        // use an actual HttpClient to make checking redirects easier
        HttpResponse<String> rsp = getPageWithGet("/manage");
        assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(notMatching(".*grant_type=refresh_token.*")));
    }

    @Test
    void testRefreshTokenWithTokenExpirationCheckDisabled_withoutRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        configureWellKnown(null, null, "authorization_code");
        var realm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        realm.setTokenExpirationCheckDisabled(true);
        jenkins.setSecurityRealm(realm);
        // login
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoWithTestGroups();
        browseLoginPage();
        assertTestUser();

        expire();
        webClient.goTo(jenkins.getSearchUrl());

        wireMock.verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(notMatching(".*grant_type=refresh_token.*")));
    }

    @Test
    void testRefreshTokenWithTokenExpirationCheckDisabled_expiredRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        configureWellKnown(null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        testRealm.setTokenExpirationCheckDisabled(true);
        jenkins.setSecurityRealm(testRealm);
        // login
        mockTokenReturnsIdTokenWithGroup();
        mockUserInfoWithTestGroups();
        browseLoginPage();
        assertTestUser();

        wireMock.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"invalid_grant\" }")));
        expire();
        webClient.goTo(jenkins.getSearchUrl(), "");

        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
    }

    @Test
    void testRefreshTokenAndTokenExpiration_expiredRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        configureWellKnown(null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        jenkins.setSecurityRealm(testRealm);
        // login
        mockTokenReturnsIdTokenWithGroup();
        mockUserInfoWithTestGroups();
        browseLoginPage();
        assertTestUser();

        wireMock.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"invalid_grant\" }")));
        expire();
        webClient.assertFails(jenkins.getSearchUrl(), 500);

        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
    }

    @Test
    void testTokenExpiration_withoutExpiresInValue() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        configureWellKnown(null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        jenkins.setSecurityRealm(testRealm);
        // login
        mockTokenReturnsIdTokenWithGroup(PluginTest::withoutExpiresIn);
        mockUserInfoWithTestGroups();
        browseLoginPage();
        var user = assertTestUser();
        OicCredentials credentials = user.getProperty(OicCredentials.class);

        assertNotNull(credentials);
        assertNull(credentials.getExpiresAtMillis());
    }

    private void expire() throws Exception {
        webClient.executeOnServer(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User user = User.get2(authentication);
            OicCredentials credentials = user.getProperty(OicCredentials.class);

            // setting currentTimestamp == 1 guarantees this will be an expired cred
            user.addProperty(new OicCredentials(
                    credentials.getAccessToken(),
                    credentials.getIdToken(),
                    credentials.getRefreshToken(),
                    60L,
                    1L,
                    60L));
            return null;
        });
    }

    @Test
    void testreadResolve_withNulls() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithValues(setUpKeyValuesWithGroup());
        mockUserInfoWithTestGroups();

        configureWellKnown(null, null);

        TestRealm realm = new TestRealm(wireMock, null, null, null, true);
        jenkins.setSecurityRealm(realm);

        assertEquals(realm, realm.readResolve());
    }

    @Test
    void testreadResolve_withNonNulls() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        mockUserInfoWithTestGroups();
        configureWellKnown("http://localhost/endSession", null);
        TestRealm realm = new TestRealm(wireMock, null, null, null, true);
        jenkins.setSecurityRealm(realm);
        assertEquals(realm, realm.readResolve());
    }

    @Test
    void testLoginUsingUserInfoEndpoint() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoWithTestGroups();
        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));
        assertAnonymous();
        browseLoginPage();
        var user = assertTestUser();
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    void testLoginUsingUserInfoWithJWT() throws Exception {
        KeyPair keyPair = createKeyPair();
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoJwtWithTestGroups(keyPair, "group1");

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous();

        browseLoginPage();

        var user = assertTestUser();
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
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues(keyPair);
        mockUserInfoJwtWithTestGroups(keyPair, TEST_USER_GROUPS);

        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithUserInfoServerUrl("http://localhost:" + wireMock.getPort() + "/userinfo")
                        .WithJwksServerUrl("http://localhost:" + wireMock.getPort() + "/jwks")
                        .WithDisableTokenValidation(false)
                        .build());

        assertAnonymous();

        browseLoginPage();

        Authentication authentication = getAuthentication();
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
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues(keyPair);
        mockUserInfoJwtWithTestGroups(keyPair, TEST_USER_GROUPS);
        TestRealm testRealm = new TestRealm.Builder(wireMock)
                .WithUserInfoServerUrl("http://localhost:" + wireMock.getPort() + "/userinfo")
                        .WithJwksServerUrl("http://localhost:" + wireMock.getPort() + "/jwks")
                        .build();
        jenkins.setSecurityRealm(testRealm);
        assertAnonymous();
        browseLoginPage();
        assertAnonymous();
        testRealm.setDisableTokenVerification(true);
        browseLoginPage();
        Authentication authentication = getAuthentication();
        assertEquals(TEST_USER_USERNAME, authentication.getPrincipal(), "Should be logged-in as " + TEST_USER_USERNAME);
    }

    @Test
    void testShouldLogUserWithoutGroupsWhenUserGroupIsMissing() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoWithGroups(null);

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous();

        browseLoginPage();

        User user = toUser(getAuthentication());
        assertTrue(user.getAuthorities().isEmpty(), "User shouldn't be part of any group");
    }

    @Test
    void testShouldLogUserWithoutGroupsWhenUserGroupIsNull() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoWithGroups(JsonNull.INSTANCE);

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous();

        browseLoginPage();

        User user = toUser(getAuthentication());
        assertTrue(user.getAuthorities().isEmpty(), "User shouldn't be part of any group");
    }

    @Test
    void testShouldLogUserWithoutGroupsWhenUserGroupIsNotAStringList() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfoWithGroups(Map.of("not", "a group"));

        jenkins.setSecurityRealm(new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo"));

        assertAnonymous();

        browseLoginPage();

        User user = toUser(getAuthentication());
        assertTrue(user.getAuthorities().isEmpty(), "User shouldn't be part of any group");
    }

    @Test
    void testNestedFieldLookup() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithValues(setUpKeyValuesNested());
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, "nested.email", "nested.groups"));
        assertAnonymous();
        browseLoginPage();
        var user = assertTestUser();
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    @Test
    void testNestedFieldLookupFromUserInfoEndpoint() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfo(Map.of(
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

        assertAnonymous();

        browseLoginPage();

        var user = assertTestUser();
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
    }

    private static void assertTestUserEmail(User user) {
        assertEquals(
                TEST_USER_EMAIL_ADDRESS,
                user.getProperty(Mailer.UserProperty.class).getAddress(),
                "Email should be " + TEST_USER_EMAIL_ADDRESS);
    }

    private static void assertTestAvatar(User user, WireMockExtension wireMock) {
        String expectedAvatarUrl = "http://localhost:%d/my-avatar.png".formatted(wireMock.getPort());
        OicAvatarProperty avatarProperty = user.getProperty(OicAvatarProperty.class);
        assertEquals(expectedAvatarUrl, avatarProperty.getAvatarUrl(), "Avatar url should be " + expectedAvatarUrl);
        assertEquals("Openid Connect Avatar", avatarProperty.getDisplayName());
        assertNull(avatarProperty.getIconFileName(), "Icon filename must be null");
    }

    private @NonNull User assertTestUser() {
        Authentication authentication = getAuthentication();
        assertEquals(TEST_USER_USERNAME, authentication.getPrincipal(), "Should be logged-in as " + TEST_USER_USERNAME);
        User user = toUser(authentication);
        assertEquals(TEST_USER_FULL_NAME, user.getFullName(), "Full name should be " + TEST_USER_FULL_NAME);
        return user;
    }

    @Test
    void testFieldLookupFromIdTokenWhenNotInUserInfoEndpoint() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();

        mockTokenReturnsIdTokenWithValues(setUpKeyValuesWithGroupAndSub());
        mockUserInfo(Map.of("sub", "", FULL_NAME_FIELD, JsonNull.INSTANCE, GROUPS_FIELD, TEST_USER_GROUPS));

        jenkins.setSecurityRealm(
                new TestRealm(wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo", "email", "groups"));
        browseLoginPage();

        Authentication authentication = getAuthentication();
        assertEquals(
                TEST_USER_USERNAME,
                authentication.getPrincipal(),
                "Should read field (ex:username) from IdToken when empty in userInfo");
        User user = toUser(authentication);
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
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithoutValues();
        mockUserInfo(Map.of(
                "sub",
                TEST_USER_USERNAME,
                FULL_NAME_FIELD,
                TEST_USER_FULL_NAME,
                "nested",
                Map.of(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS, GROUPS_FIELD, TEST_USER_GROUPS)));

        jenkins.setSecurityRealm(new TestRealm(
                wireMock, "http://localhost:" + wireMock.getPort() + "/userinfo", "nested.email", "nested.groups"));

        assertAnonymous();

        browseLoginPage();

        var user = assertTestUser();
        assertTestUserEmail(user);
        assertTestUserIsMemberOfTestGroups(user);
        assertEquals(2, user.getAuthorities().size(), "User should be in 2 groups");
    }

    @Test
    void testLastGrantedAuthoritiesProperty() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();

        mockTokenReturnsIdTokenWithValues(setUpKeyValuesWithGroup());

        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, false));

        assertAnonymous();

        browseLoginPage();

        var user = assertTestUser();

        assertTestUserEmail(user);
        assertEquals(2, user.getAuthorities().size(), "User should be in 2 groups");

        LastGrantedAuthoritiesProperty userProperty = user.getProperty(LastGrantedAuthoritiesProperty.class);
        assertEquals(
                3, userProperty.getAuthorities2().size(), "Property should specify 3 groups (2 + 'authenticated')");

        HtmlPage configure = Jenkins.getVersion().isNewerThan(new VersionNumber("2.467"))
                ? webClient.goTo("me/account/")
                : webClient.goTo("me/configure");
        jenkinsRule.submit(configure.getFormByName("config"));
        user = User.getById(TEST_USER_USERNAME, false);
        assertEquals(2, user.getAuthorities().size(), "User should still be in 2 groups");
        userProperty = user.getProperty(LastGrantedAuthoritiesProperty.class);
        assertEquals(
                3,
                userProperty.getAuthorities2().size(),
                "Property should still specify 3 groups (2 + 'authenticated')");
    }

    private void configureWellKnown(@CheckForNull String endSessionUrl, @CheckForNull List<String> scopesSupported) {
        configureWellKnown(endSessionUrl, scopesSupported, "authorization_code");
    }

    private void configureWellKnown(
            @CheckForNull String endSessionUrl,
            @CheckForNull List<String> scopesSupported,
            @CheckForNull String... grantTypesSupported) {
        // scopes_supported may not be null, but is not required to be present.
        // if present it must minimally be "openid"
        // Claims with zero elements MUST be omitted from the response.

        Map<String, Object> values = new HashMap<>(Map.of(
                "authorization_endpoint",
                "http://localhost:" + wireMock.getPort() + "/authorization",
                "token_endpoint",
                "http://localhost:" + wireMock.getPort() + "/token",
                "userinfo_endpoint",
                "http://localhost:" + wireMock.getPort() + "/userinfo",
                "jwks_uri",
                "http://localhost:" + wireMock.getPort() + "/jwks",
                "issuer",
                TestRealm.ISSUER,
                "subject_types_supported",
                List.of("public")));
        if (scopesSupported != null && !scopesSupported.isEmpty()) {
            values.put("scopes_supported", scopesSupported);
        }
        if (endSessionUrl != null) {
            values.put("end_session_endpoint", endSessionUrl);
        }
        if (grantTypesSupported.length != 0) {
            values.put("grant_types_supported", grantTypesSupported);
        }

        wireMock.stubFor(get(urlPathEqualTo("/well.known"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withBody(toJson(values))));
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
        assertEquals("http://provider/logout?state=null", logoutURL[0]);
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
                "http://provider/logout?state=null&post_logout_redirect_uri=http%3A%2F%2Fsee.it%2F%3Fcat%26color%3Dwhite",
                logoutURL[0]);
    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private String createIdToken(PrivateKey privateKey, Map<String, Object> keyValues) throws Exception {
        JsonWebSignature.Header header =
                new JsonWebSignature.Header().setAlgorithm("RS256").setKeyId("jwks_key_id");
        long now = Clock.systemUTC().millis() / 1000;
        IdToken.Payload payload = new IdToken.Payload()
                .setExpirationTimeSeconds(now + 60L)
                .setIssuedAtTimeSeconds(now)
                .setIssuer(TestRealm.ISSUER)
                .setSubject(TEST_USER_USERNAME)
                .setAudience(Collections.singletonList(TestRealm.CLIENT_ID))
                .setNonce("nonce");
        for (Map.Entry<String, Object> keyValue : keyValues.entrySet()) {
            payload.set(keyValue.getKey(), keyValue.getValue());
        }

        return JsonWebSignature.signUsingRsaSha256(privateKey, GsonFactory.getDefaultInstance(), header, payload);
    }

    private String createUserInfoJWT(PrivateKey privateKey, String userInfo) throws Exception {

        JsonWebSignature.Header header =
                new JsonWebSignature.Header().setAlgorithm("RS256").setKeyId("jwks_key_id");

        JsonWebToken.Payload payload = new JsonWebToken.Payload();
        for (Map.Entry<String, JsonElement> keyValue :
                parseString(userInfo).getAsJsonObject().entrySet()) {
            var value = keyValue.getValue();
            if (value.isJsonArray()) {
                payload.set(keyValue.getKey(), new Gson().fromJson(value, String[].class));
            } else {
                payload.set(keyValue.getKey(), value.getAsString());
            }
        }

        return JsonWebSignature.signUsingRsaSha256(privateKey, GsonFactory.getDefaultInstance(), header, payload);
    }

    @Test
    void testLoginWithMissingIdTokenShouldBeRefused() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdToken(null);
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, null, null));
        assertAnonymous();
        webClient.assertFails(jenkins.getSecurityRealm().getLoginUrl(), 500);
    }

    @Test
    void testLoginWithUnreadableIdTokenShouldBeRefused() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdToken("This is not an IdToken");
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, null, null));
        assertAnonymous();
        webClient.assertFails(jenkins.getSecurityRealm().getLoginUrl(), 500);
    }

    @Test
    void loginWithCheckTokenSuccess() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        configureTestRealm(belongsToGroup("group1"));
        assertAnonymous();
        browseLoginPage();
        assertTestUser();
    }

    @Test
    void loginWithCheckTokenFailure() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        configureTestRealm(belongsToGroup("missing-group"));
        assertAnonymous();
        webClient.setThrowExceptionOnFailingStatusCode(false);
        browseLoginPage();
        assertAnonymous();
    }

    @Test
    @Issue("SECURITY-3441")
    void loginWithIncorrectIssuerFails() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithIssuer("another_issuer").WithDisableTokenValidation(false).build());
        assertAnonymous();
        webClient.setThrowExceptionOnFailingStatusCode(false);
        browseLoginPage();
        assertAnonymous();
    }

    @Test
    @Issue("SECURITY-3441")
    void loginWithIncorrectAudienceFails() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        mockTokenReturnsIdTokenWithGroup();
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithClient("another_client_id", "client_secret")
                        .WithDisableTokenValidation(false)
                        .build());
        assertAnonymous();
        webClient.setThrowExceptionOnFailingStatusCode(false);
        browseLoginPage();
        assertAnonymous();
    }

    @Test
    void testAccessUsingJenkinsApiTokens() throws Exception {
        mockAuthorizationRedirectsToFinishLogin();
        configureWellKnown(null, null, "authorization_code");
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        // explicitly ensure allowTokenAccessWithoutOicSession is disabled
        TestRealm testRealm = (TestRealm) jenkins.getSecurityRealm();
        testRealm.setAllowTokenAccessWithoutOicSession(false);

        // login and assert normal auth is working
        mockTokenReturnsIdTokenWithGroup(PluginTest::withoutRefreshToken);
        mockUserInfoWithTestGroups();
        browseLoginPage();
        assertTestUser();

        // create a jenkins api token for the test user
        String token = User.getById(TEST_USER_USERNAME, false)
                .getProperty(ApiTokenProperty.class)
                .generateNewToken("foo")
                .plainValue;

        // validate that the token can be used
        HttpResponse<String> rsp = getPageWithGet(TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));

        assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));

        // expired oic session tokens, do not refreshed
        expire();

        // the default behavior expects there to be a valid oic session, so token based
        // access should now fail (unauthorized)
        rsp = getPageWithGet(TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));

        // enable "traditional api token access"
        testRealm.setAllowTokenAccessWithoutOicSession(true);

        // verify that jenkins api token is now working again
        rsp = getPageWithGet(TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));
        assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));
    }

    private static @NonNull Consumer<OicSecurityRealm> belongsToGroup(String groupName) {
        return sc -> {
            sc.setTokenFieldToCheckKey("contains(groups, '" + groupName + "')");
            sc.setTokenFieldToCheckValue("true");
        };
    }

    /** Generate JWKS entry with public key of keyPair */
    String encodePublicKey(KeyPair keyPair) {
        final RSAPublicKey rsaPKey = (RSAPublicKey) (keyPair.getPublic());
        return "\"n\":\""
                + Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(rsaPKey.getModulus().toByteArray())
                + "\",\"e\":\""
                + Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(rsaPKey.getPublicExponent().toByteArray())
                + "\",\"alg\":\"RS256\",\"kty\":\"RSA\"";
    }

    /**
     * Gets the authentication object from the web client.
     *
     * @return the authentication object
     */
    private Authentication getAuthentication() {
        try {
            return webClient.executeOnServer(Jenkins::getAuthentication2);
        } catch (Exception e) {
            // safely ignore all exceptions, the method never throws anything
            return null;
        }
    }

    private static @NonNull Map<String, Object> setUpKeyValuesNoGroup() {
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        return keyValues;
    }

    private static @NonNull Map<String, Object> setUpKeyValuesWithGroup(String[] groups) {
        var keyValues = setUpKeyValuesNoGroup();
        keyValues.put(GROUPS_FIELD, groups);
        return keyValues;
    }

    private static @NonNull Map<String, Object> setUpKeyValuesWithGroup() {
        return setUpKeyValuesWithGroup(TEST_USER_GROUPS);
    }

    private static @NonNull Map<String, Object> setUpKeyValuesWithGroupAndSub() {
        var keyValues = setUpKeyValuesWithGroup();
        keyValues.put("sub", TEST_USER_USERNAME);
        return keyValues;
    }

    private static @NonNull Map<String, Object> setUpKeyValuesNested() {
        return Map.of(
                "nested",
                Map.of(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS, GROUPS_FIELD, TEST_USER_GROUPS),
                FULL_NAME_FIELD,
                TEST_USER_FULL_NAME);
    }

    private void mockUserInfoWithTestGroups() {
        mockUserInfoWithGroups(TEST_USER_GROUPS);
    }

    private void mockUserInfoWithGroups(@Nullable Object groups) {
        mockUserInfo(getUserInfo(groups, null));
    }

    private void mockUserInfoWithAvatar(WireMockExtension wireMock) {
        mockUserInfo(getUserInfo(null, wireMock));
    }

    private void mockUserInfoJwtWithTestGroups(KeyPair keyPair, Object testUserGroups) throws Exception {
        wireMock.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/jwt")
                        .withBody(createUserInfoJWT(keyPair.getPrivate(), toJson(getUserInfo(testUserGroups, null))))));
    }

    private void mockUserInfo(Map<String, Object> userInfo) {
        wireMock.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(toJson(userInfo))));
    }

    private static Map<String, Object> getUserInfo(@Nullable Object groups, WireMockExtension wireMock) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("sub", TEST_USER_USERNAME);
        userInfo.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        userInfo.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        if (groups != null) {
            userInfo.put(GROUPS_FIELD, groups);
        }
        if (wireMock != null) {
            userInfo.put("picture", "http://localhost:" + wireMock.getPort() + "/my-avatar.png");
        }
        return userInfo;
    }

    private static String toJson(Object o) {
        return new Gson().newBuilder().serializeNulls().create().toJson(o);
    }

    private void mockTokenReturnsIdTokenWithGroup() throws Exception {
        mockTokenReturnsIdTokenWithValues(setUpKeyValuesWithGroup());
    }

    private void mockTokenReturnsIdTokenWithoutValues() throws Exception {
        mockTokenReturnsIdTokenWithValues(Map.of());
    }

    private void mockTokenReturnsIdTokenWithoutValues(KeyPair keyPair) throws Exception {
        mockTokenReturnsIdTokenWithValues(Map.of(), keyPair);
    }

    private void mockTokenReturnsIdTokenWithValues(Map<String, Object> keyValues) throws Exception {
        mockTokenReturnsIdTokenWithValues(keyValues, createKeyPair());
    }

    private void mockTokenReturnsIdTokenWithValues(Map<String, Object> keyValues, KeyPair keyPair) throws Exception {
        mockTokenReturnsIdToken(createIdToken(keyPair.getPrivate(), keyValues));
    }

    @SafeVarargs
    private void mockTokenReturnsIdTokenWithGroup(@CheckForNull Consumer<Map<String, String>>... tokenAcceptors)
            throws Exception {
        var keyPair = createKeyPair();
        mockTokenReturnsIdToken(createIdToken(keyPair.getPrivate(), setUpKeyValuesWithGroup()), tokenAcceptors);
    }

    private void mockTokenReturnsIdToken(@CheckForNull String idToken) {
        mockTokenReturnsIdToken(idToken, new Consumer[0]);
    }

    @SafeVarargs
    private void mockTokenReturnsIdToken(
            @CheckForNull String idToken, @CheckForNull Consumer<Map<String, String>>... tokenAcceptors) {
        var token = new HashMap<String, String>();
        token.put("access_token", "AcCeSs_ToKeN");
        token.put("token_type", "Bearer");
        token.put("expires_in", "3600");
        token.put("refresh_token", "ReFrEsH_ToKeN");
        token.put("example_parameter", "example_value");
        if (idToken != null) {
            token.put("id_token", idToken);
        }
        if (tokenAcceptors != null) {
            Arrays.stream(tokenAcceptors).forEach(a -> a.accept(token));
        }
        wireMock.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(toJson(token))));
    }

    private static @Nullable User toUser(Authentication authentication) {
        return User.get(String.valueOf(authentication.getPrincipal()), false, Map.of());
    }

    private static void withoutRefreshToken(Map<String, String> token) {
        token.compute("refresh_token", (o, n) -> null);
    }

    private static void withoutExpiresIn(Map<String, String> token) {
        token.compute("expires_in", (o, n) -> null);
    }
}

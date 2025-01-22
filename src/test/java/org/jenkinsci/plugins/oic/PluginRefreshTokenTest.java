package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.oauth2.sdk.GrantType;
import java.net.http.HttpResponse;
import jenkins.model.Jenkins;
import org.hamcrest.MatcherAssert;
import org.jenkinsci.plugins.oic.plugintest.Mocks;
import org.jenkinsci.plugins.oic.plugintest.TestHelper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.Url;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.hamcrest.Matchers.is;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
@Url("https://jenkins.io/blog/2018/01/13/jep-200/")
public class PluginRefreshTokenTest {

    private static final String[] TEST_USER_GROUPS_REFRESHED = new String[] {"group1", "group2", "group3"};

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
    public void testConfigurationWithAutoConfiguration_withRefreshToken() throws Exception {
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults().WithAutomanualconfigure(true).build();
        jenkins.setSecurityRealm(testRealm);
        assertTrue(
                "Refresh token should be enabled",
                testRealm
                        .getServerConfiguration()
                        .toProviderMetadata()
                        .getGrantTypes()
                        .contains(GrantType.REFRESH_TOKEN));
    }

    @Test
    public void testRefreshToken_validAndExtendedToken() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code", "refresh_token");
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true));
        // user groups on first login
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.browseLoginPage(webClient, jenkins);
        var user = TestHelper.assertTestUser(webClient);
        assertFalse(
                "User should not be part of group " + TEST_USER_GROUPS_REFRESHED[2],
                user.getAuthorities().contains(TEST_USER_GROUPS_REFRESHED[2]));

        // refresh user with different groups
        Mocks.mockTokenReturnsIdTokenWithValues(
                wireMockRule, TestHelper.setUpKeyValuesWithGroup(TEST_USER_GROUPS_REFRESHED));
        Mocks.mockUserInfoWithGroups(wireMockRule, TEST_USER_GROUPS_REFRESHED);
        TestHelper.expire(webClient);
        webClient.goTo(jenkins.getSearchUrl());

        user = TestHelper.assertTestUser(webClient);
        assertTrue(
                "User should be part of group " + TEST_USER_GROUPS_REFRESHED[2],
                user.getAuthorities().contains(TEST_USER_GROUPS_REFRESHED[2]));

        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
    }

    @Test
    public void testRefreshTokenAndTokenExpiration_withoutRefreshToken() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code");
        jenkins.setSecurityRealm(new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true));
        // login
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule, TestHelper::withoutRefreshToken);
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertTestUser(webClient);
        // expired token not refreshed
        TestHelper.expire(webClient);
        // use an actual HttpClient to make checking redirects easier
        HttpResponse<String> rsp = TestHelper.getPageWithGet(jenkinsRule, "/manage");
        MatcherAssert.assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));
        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(notMatching(".*grant_type=refresh_token.*")));
    }

    @Test
    public void testRefreshTokenWithTokenExpirationCheckDisabled_withoutRefreshToken() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code");
        var realm = new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true);
        realm.setTokenExpirationCheckDisabled(true);
        jenkins.setSecurityRealm(realm);
        // login
        Mocks.mockTokenReturnsIdTokenWithoutValues(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertTestUser(webClient);

        TestHelper.expire(webClient);
        webClient.goTo(jenkins.getSearchUrl());

        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(notMatching(".*grant_type=refresh_token.*")));
    }

    @Test
    public void testRefreshTokenWithTokenExpirationCheckDisabled_expiredRefreshToken() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true);
        testRealm.setTokenExpirationCheckDisabled(true);
        jenkins.setSecurityRealm(testRealm);
        // login
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertTestUser(webClient);

        wireMockRule.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"invalid_grant\" }")));
        TestHelper.expire(webClient);
        webClient.goTo(jenkins.getSearchUrl(), "");

        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
    }

    @Test
    public void testRefreshTokenAndTokenExpiration_expiredRefreshToken() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMockRule, null, EMAIL_FIELD, GROUPS_FIELD, true);
        jenkins.setSecurityRealm(testRealm);
        // login
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertTestUser(webClient);

        wireMockRule.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"invalid_grant\" }")));
        TestHelper.expire(webClient);
        webClient.assertFails(jenkins.getSearchUrl(), 500);

        verify(postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
    }
}

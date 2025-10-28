package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.browseLoginPage;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureWellKnown;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.expire;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.getPageWithGet;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithTestGroups;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.User;
import java.net.http.HttpResponse;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import org.jenkinsci.plugins.oic.plugintest.PluginTestHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.rules.DisableOnDebug;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
@WithJenkins
public class PluginApiTokenTest {

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
        if (new DisableOnDebug(null).isDebugging()) {
            webClient.getOptions().setTimeout(0);
        }
    }

    @Test
    void testAccessJenkinsUsingApiTokens() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code");

        TestRealm testRealm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithAutomanualconfigure(true)
                        // explicitly ensure allowTokenAccessWithoutOicSession is disabled
                        .WithAllowTokenAccessWithoutOicSession(false)
                        .build();

        jenkins.setSecurityRealm(testRealm);

        // login and assert normal auth is working
        mockTokenReturnsIdTokenWithGroup(wireMock, PluginTestHelper::withoutRefreshToken);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);

        // create a jenkins api token for the test user
        User userById = User.getById(TEST_USER_USERNAME, false);
        assertNotNull(userById);
        String token = userById.getProperty(ApiTokenProperty.class).generateNewToken("foo").plainValue;

        // validate that the token can be used
        HttpResponse<String> rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));

        assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));

        // expired oic session tokens, do not refreshed
        expire(webClient);

        // the default behavior expects there to be a valid oic session, so token based
        // access should now fail (unauthorized)
        rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));

        // enable "traditional api token access"
        testRealm.setAllowTokenAccessWithoutOicSession(true);

        // verify that jenkins api token is now working again
        rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));
        assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));

        // logout
        rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/logout");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));
    }
}

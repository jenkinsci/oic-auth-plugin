package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.model.User;
import java.net.http.HttpResponse;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import org.hamcrest.MatcherAssert;
import org.jenkinsci.plugins.oic.plugintest.Mocks;
import org.jenkinsci.plugins.oic.plugintest.TestHelper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
public class PluginApiTokenTest {

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
    public void testAccessJenkinsUsingApiTokens() throws Exception {
        Mocks.mockAuthorizationRedirectsToFinishLogin(wireMockRule, jenkins);
        TestHelper.configureWellKnown(wireMockRule, null, null, "authorization_code");

        TestRealm testRealm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults()
                        .WithAutomanualconfigure(true)
                        // explicitly ensure allowTokenAccessWithoutOicSession is disabled
                        .WithAllowTokenAccessWithoutOicSession(false)
                        .build();

        jenkins.setSecurityRealm(testRealm);

        // login and assert normal auth is working
        Mocks.mockTokenReturnsIdTokenWithGroup(wireMockRule, TestHelper::withoutRefreshToken);
        Mocks.mockUserInfoWithTestGroups(wireMockRule);
        TestHelper.browseLoginPage(webClient, jenkins);
        TestHelper.assertTestUser(webClient);

        User user = User.getById(TestHelper.TEST_USER_USERNAME, false);
        assertNotNull("User must not be null", user);

        // create a jenkins api token for the test user
        String token = user.getProperty(ApiTokenProperty.class).generateNewToken("foo").plainValue;

        // validate that the token can be used
        HttpResponse<String> rsp =
                TestHelper.getPageWithGet(jenkinsRule, TestHelper.TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        MatcherAssert.assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));

        MatcherAssert.assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));

        // expired oic session tokens, do not refreshed
        TestHelper.expire(webClient);

        // the default behavior expects there to be a valid oic session, so token based
        // access should now fail (unauthorized)
        rsp = TestHelper.getPageWithGet(jenkinsRule, TestHelper.TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        MatcherAssert.assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));

        // enable "traditional api token access"
        testRealm.setAllowTokenAccessWithoutOicSession(true);

        // verify that jenkins api token is now working again
        rsp = TestHelper.getPageWithGet(jenkinsRule, TestHelper.TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        MatcherAssert.assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));
        MatcherAssert.assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));

        // logout
        rsp = TestHelper.getPageWithGet(jenkinsRule, TestHelper.TEST_USER_USERNAME, token, "/logout");
        MatcherAssert.assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));
    }
}

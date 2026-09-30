package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertAnonymous;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertNoAvatar;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestAvatar;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.browseLoginPage;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureWellKnown;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithoutValues;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithAvatarUrl;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.User;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.avatar.AvatarHandler;
import org.jenkinsci.plugins.oic.avatar.NoAvatarHandler;
import org.jenkinsci.plugins.oic.avatar.ServeFromURLAvatarHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Tests the admin selectable avatar strategies ({@link AvatarHandler}).
 *
 * @see PluginTest#testLoginUsingUserInfoEndpointWithAvatar()
 */
@WithJenkins
class AvatarTest {

    private static final String AVATAR_PATH = "/my-avatar.png";

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
        this.jenkins = jenkinsRule.getInstance();
        this.webClient = jenkinsRule.createWebClient();
    }

    @Test
    void serveFromProviderHandler() throws Exception {
        User user = login(new ServeFromURLAvatarHandler());
        assertTestAvatar(user, avatarUrl());
    }

    @Test
    void noAvatarHandler() throws Exception {
        // no stub for AVATAR_PATH - nothing may be fetched
        User user = login(new NoAvatarHandler());
        assertNoAvatar(user);
    }

    @Test
    void noAvatarHandlerClearsAnExistingAvatar() throws Exception {
        User user = login(new ServeFromURLAvatarHandler());
        user = relogin(new NoAvatarHandler());
        assertNoAvatar(user);
    }

    /**
     * Stubs the well known / authorization / token / userinfo endpoints; the {@code picture} claim
     * points at {@link #AVATAR_PATH} on WireMock's plain HTTP port.
     */
    /**
     * The plain {@code http} URL the avatar is published at.
     * <p>
     * Deliberately not {@link WireMockExtension#url(String)}: that returns an {@code https} URL as soon as an https
     * port is enabled (as it is for this class), which would point every test at the self signed port.
     */
    private String avatarUrl() {
        return "http://localhost:" + wireMock.getPort() + AVATAR_PATH;
    }

    private void mockLoginFlow() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithAvatarUrl(wireMock, avatarUrl());
        configureWellKnown(wireMock, null, null);
    }

    /**
     * Configures a realm using the given handler, logs in and returns the logged-in user.
     */
    private User login(AvatarHandler avatarHandler) throws Exception {
        mockLoginFlow();
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithAutomanualconfigure(true)
                        .WithAvatarHandler(avatarHandler)
                        .build());
        assertAnonymous(webClient);
        browseLoginPage(webClient, jenkins);
        return assertTestUser(webClient);
    }

    /**
     * Swaps the handler on the realm and logs in again with a fresh session (changing the security
     * realm invalidates the current one).
     */
    private User relogin(AvatarHandler avatarHandler) throws Exception {
        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithAutomanualconfigure(true)
                        .WithAvatarHandler(avatarHandler)
                        .build());
        webClient = jenkinsRule.createWebClient();
        browseLoginPage(webClient, jenkins);
        return assertTestUser(webClient);
    }
}

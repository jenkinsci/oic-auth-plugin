package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertAnonymous;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertCachedAvatar;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertNoAvatar;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertNoCachedAvatarFile;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestAvatar;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_ACCESS_TOKEN;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_ENCODED_AVATAR;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.browseLoginPage;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureWellKnown;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithoutValues;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithAvatarUrl;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.User;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import jenkins.model.Jenkins;
import org.htmlunit.Page;
import org.htmlunit.WebResponse;
import org.jenkinsci.plugins.oic.avatar.AvatarDownloadService;
import org.jenkinsci.plugins.oic.avatar.AvatarHandler;
import org.jenkinsci.plugins.oic.avatar.AvatarProperty;
import org.jenkinsci.plugins.oic.avatar.NoAvatarHandler;
import org.jenkinsci.plugins.oic.avatar.ServeFromJenkinsAvatarHandler;
import org.jenkinsci.plugins.oic.avatar.ServeFromJenkinsUsingAccessTokenAvatarHandler;
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

    private static final byte[] AVATAR_BYTES = Base64.getDecoder().decode(TEST_ENCODED_AVATAR);

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

    // ---------------------------------------------------------------- default

    @Test
    void defaultHandlerIsServeFromUrlAndKeepsLegacyBehaviour() throws Exception {
        // deliberately not calling WithAvatarHandler - the default must be preserved
        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults().WithAutomanualconfigure(true).build();
        assertInstanceOf(
                ServeFromURLAvatarHandler.class,
                realm.getAvatarHandler(),
                "serving from the provider must remain the default");

        // no stub for AVATAR_PATH: with failOnUnmatchedRequests(true) this also proves
        // Jenkins never fetches the image itself in this mode.
        mockLoginFlow();
        jenkins.setSecurityRealm(realm);
        assertAnonymous(webClient);
        assertTestAvatar(null, wireMock);
        browseLoginPage(webClient, jenkins);
        User user = assertTestUser(webClient);
        assertTestAvatar(user, avatarUrl());
    }

    @Test
    void explicitServeFromProviderHandlerStoresTheClaimUrl() throws Exception {
        User user = login(new ServeFromURLAvatarHandler());
        assertTestAvatar(user, avatarUrl());
    }

    // --------------------------------------------------------------- noAvatar

    @Test
    void noAvatarHandlerStoresNothing() throws Exception {
        // no stub for AVATAR_PATH - nothing may be fetched
        User user = login(new NoAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
        assertNoCachedAvatarFile(user);
    }

    @Test
    void noAvatarHandlerClearsAnExistingAvatar() throws Exception {
        stubAvatar("image/png", AVATAR_BYTES);
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertCachedAvatar(user, AVATAR_BYTES);

        user = relogin(new NoAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
    }

    // --------------------------------------------------------- serveFromJenkins

    @Test
    void serveFromJenkinsCachesAndServesTheImageItself() throws Exception {
        stubAvatar("image/png", AVATAR_BYTES);
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();

        String avatarUrl = assertCachedAvatar(user, AVATAR_BYTES);

        WebResponse response = fetch(webClient, avatarUrl);
        assertEquals(200, response.getStatusCode(), "the cached avatar should be served");
        assertEquals("image/png", response.getResponseHeaderValue("Content-Type"));
        assertEquals("nosniff", response.getResponseHeaderValue("X-Content-Type-Options"));
        try (var in = response.getContentAsStream()) {
            assertArrayEquals(AVATAR_BYTES, in.readAllBytes(), "the served bytes should be the provider bytes");
        }
    }

    @Test
    void serveFromJenkinsRejectsNotFound() throws Exception {
        wireMock.stubFor(get(urlPathEqualTo(AVATAR_PATH)).willReturn(aResponse().withStatus(404)));
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
    }

    @Test
    void serveFromJenkinsRejectsHtmlContentType() throws Exception {
        stubAvatar("text/html", "<html><body>not an image</body></html>".getBytes(StandardCharsets.UTF_8));
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
    }

    /**
     * The declared {@code Content-Type} claims PNG but the body is not one of GIF / JPEG / PNG, so
     * magic byte sniffing - not the provider's header - must decide.
     */
    @Test
    void serveFromJenkinsRejectsNonImageBodyDespiteImagePngContentType() throws Exception {
        stubAvatar(
                "image/png",
                "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"/>"
                        .getBytes(StandardCharsets.UTF_8));
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
    }

    @Test
    void serveFromJenkinsRejectsOversizedAvatarWithContentLength() throws Exception {
        stubAvatar("image/png", oversizedPng());
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
    }

    /**
     * Same as {@link #serveFromJenkinsRejectsOversizedAvatarWithContentLength()} but chunked, so
     * there is no {@code Content-Length} to short circuit on and the streaming cap has to catch it.
     */
    @Test
    void serveFromJenkinsRejectsOversizedAvatarWhenChunked() throws Exception {
        wireMock.stubFor(get(urlPathEqualTo(AVATAR_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "image/png")
                        .withBody(oversizedPng())
                        .withChunkedDribbleDelay(4, 200)));
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
    }

    // ------------------------------------- serveFromJenkinsUsingAccessToken

    @Test
    void serveFromJenkinsUsingAccessTokenSendsBearerOverHttps() throws Exception {
        String httpsBaseUrl = wireMock.getRuntimeInfo().getHttpsBaseUrl();
        String avatarUrl = httpsBaseUrl + AVATAR_PATH;

        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithAvatarUrl(wireMock, avatarUrl);
        wireMock.stubFor(get(urlPathEqualTo(AVATAR_PATH))
                .withHeader("Authorization", equalTo("Bearer " + TEST_ACCESS_TOKEN))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "image/png")
                        .withBody(AVATAR_BYTES)));

        jenkins.setSecurityRealm(new TestRealm.Builder(wireMock, true)
                .WithMinimalDefaults()
                        .WithUserInfoServerUrl(httpsBaseUrl + "/userinfo")
                        .WithDisableSslVerification(true)
                        .WithAvatarHandler(new ServeFromJenkinsUsingAccessTokenAvatarHandler())
                        .build());
        // the web client talks to the OP over TLS as well
        webClient.getOptions().setUseInsecureSSL(true);
        browseLoginPage(webClient, jenkins);
        User user = assertTestUser(webClient);
        awaitDownloads();

        assertCachedAvatar(user, AVATAR_BYTES);
        wireMock.verify(getRequestedFor(urlPathEqualTo(AVATAR_PATH))
                .withHeader("Authorization", equalTo("Bearer " + TEST_ACCESS_TOKEN)));
    }

    /**
     * A bearer token must never be put on a cleartext connection; the image is fetched anonymously.
     */
    @Test
    void serveFromJenkinsUsingAccessTokenDoesNotSendBearerOverPlainHttp() throws Exception {
        wireMock.stubFor(get(urlPathEqualTo(AVATAR_PATH))
                .withHeader("Authorization", absent())
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "image/png")
                        .withBody(AVATAR_BYTES)));

        User user = login(new ServeFromJenkinsUsingAccessTokenAvatarHandler());
        awaitDownloads();

        wireMock.verify(getRequestedFor(urlPathEqualTo(AVATAR_PATH)).withHeader("Authorization", absent()));
        assertCachedAvatar(user, AVATAR_BYTES);
    }

    // -------------------------------------------------------- mode switching

    @Test
    void switchingModesLeavesNothingBehind() throws Exception {
        stubAvatar("image/png", AVATAR_BYTES);

        // 1. cached by Jenkins
        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertCachedAvatar(user, AVATAR_BYTES);

        // 2. back to serving from the provider: the cached file must be gone
        user = relogin(new ServeFromURLAvatarHandler());
        awaitDownloads();
        assertTestAvatar(user, avatarUrl());
        assertNoCachedAvatarFile(user);

        // 3. no avatar at all
        user = relogin(new NoAvatarHandler());
        awaitDownloads();
        assertNoAvatar(user);
    }

    // --------------------------------------------------------------- caching

    @Test
    void avatarIsNotRefetchedWhileFresh() throws Exception {
        stubAvatar("image/png", AVATAR_BYTES);

        User user = login(new ServeFromJenkinsAvatarHandler());
        awaitDownloads();
        assertCachedAvatar(user, AVATAR_BYTES);

        // second login with an unchanged claim url must not hit the provider again
        webClient = jenkinsRule.createWebClient();
        browseLoginPage(webClient, jenkins);
        user = assertTestUser(webClient);
        awaitDownloads();

        wireMock.verify(1, getRequestedFor(urlPathEqualTo(AVATAR_PATH)));

        AvatarProperty avatarProperty = user.getProperty(AvatarProperty.class);
        assertNotNull(avatarProperty);
        assertTrue(AvatarProperty.CACHE_TTL_MS > 0, "there should be a positive cache TTL");
        assertTrue(avatarProperty.isFreshFor(avatarUrl()), "should be fresh for the same claim url");
        assertFalse(
                avatarProperty.isFreshFor("http://example.invalid/someone-else.png"),
                "should not be fresh for a different claim url");
    }

    // ---------------------------------------------------- empty property drop

    /**
     * An {@code AvatarProperty} carrying no data must remove itself on load
     * ({@code readResolve() -> null}), so a user without an avatar has no property at all.
     */
    @Test
    void emptyAvatarPropertyIsDroppedOnReload() throws Exception {
        User user = login(new ServeFromURLAvatarHandler());
        assertNotNull(user.getProperty(AvatarProperty.class), "precondition: the property exists");

        AvatarProperty.clear(user);
        user.save();

        // force the user to be re-read from disk
        User.reload();
        User reloaded = User.getById(TEST_USER_USERNAME, false);
        assertNotNull(reloaded, "the user should still exist on disk");
        assertNull(
                reloaded.getProperty(AvatarProperty.class),
                "an empty AvatarProperty must remove itself when loaded from disk");
        assertThat(reloaded.getId(), is(TEST_USER_USERNAME));
    }

    // ----------------------------------------------------------------- tools

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

    private void stubAvatar(String contentType, byte[] body) {
        wireMock.stubFor(get(urlPathEqualTo(AVATAR_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", contentType)
                        .withBody(body)));
    }

    /** A body that starts with valid PNG magic bytes but exceeds {@link AvatarDownloadService#MAX_SIZE_BYTES}. */
    private static byte[] oversizedPng() {
        byte[] oversized = new byte[(int) AvatarDownloadService.MAX_SIZE_BYTES + 1024];
        System.arraycopy(AVATAR_BYTES, 0, oversized, 0, AVATAR_BYTES.length);
        return oversized;
    }

    private static void awaitDownloads() throws InterruptedException {
        AvatarDownloadService service = AvatarDownloadService.get();
        assertTrue(service.awaitIdle(Duration.ofSeconds(30)), "the avatar download queue should have drained");
        // awaitIdle inspects the queue and the active count, and there is a narrow window in which a
        // task has been taken off the queue but its worker is not yet counted as active, so re-check
        Thread.sleep(200);
        assertTrue(service.awaitIdle(Duration.ofSeconds(30)), "the avatar download queue should have drained");
    }

    private static WebResponse fetch(JenkinsRule.WebClient webClient, String url) throws Exception {
        webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        Page page = webClient.getPage(url);
        return page.getWebResponse();
    }
}

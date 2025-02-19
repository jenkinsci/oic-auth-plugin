package org.jenkinsci.plugins.oic.plugintest;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.google.gson.Gson;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.tasks.UserAvatarResolver;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicAvatarProperty;
import org.jenkinsci.plugins.oic.OicCredentials;
import org.jenkinsci.plugins.oic.OicSecurityRealm;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.xml.sax.SAXException;

import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PluginTestHelper {

    public static final String TEST_USER_USERNAME = "testUser";
    public static final String TEST_USER_EMAIL_ADDRESS = "test@jenkins.oic";
    public static final String TEST_USER_FULL_NAME = "Oic Test User";
    public static final String[] TEST_USER_GROUPS = new String[] {"group1", "group2"};

    public static void browseLoginPage(JenkinsRule.WebClient webClient, Jenkins jenkins)
            throws IOException, SAXException {
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());
    }

    public static @NonNull User assertTestUser(JenkinsRule.WebClient webClient) {
        Authentication authentication = getAuthentication(webClient);
        assertEquals(
                PluginTestHelper.TEST_USER_USERNAME,
                authentication.getPrincipal(),
                "Should be logged-in as " + PluginTestHelper.TEST_USER_USERNAME);
        User user = toUser(authentication);
        assertEquals(
                PluginTestHelper.TEST_USER_FULL_NAME,
                user.getFullName(),
                "Full name should be " + PluginTestHelper.TEST_USER_FULL_NAME);
        return user;
    }

    /**
     * Gets the authentication object from the web client.
     *
     * @return the authentication object
     */
    public static Authentication getAuthentication(JenkinsRule.WebClient webClient) {
        try {
            return webClient.executeOnServer(Jenkins::getAuthentication2);
        } catch (Exception e) {
            // safely ignore all exceptions, the method never throws anything
            return null;
        }
    }

    public static @Nullable User toUser(Authentication authentication) {
        return User.get(String.valueOf(authentication.getPrincipal()), false, Map.of());
    }

    public static void expire(JenkinsRule.WebClient webClient) throws Exception {
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

    public static void withoutRefreshToken(Map<String, String> token) {
        token.compute("refresh_token", (o, n) -> null);
    }

    public static HttpResponse<String> getPageWithGet(@CheckForNull JenkinsRule jenkinsRule, String url)
            throws IOException, InterruptedException {
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
     *
     * @param user  - The user id
     * @param token - the password api token to user
     * @param url   - the url to request
     * @return HttpResponse
     * @throws IOException
     * @throws InterruptedException
     */
    public static HttpResponse<String> getPageWithGet(
            @CheckForNull JenkinsRule jenkinsRule, String user, String token, String url)
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

    public static String toJson(Object o) {
        return new Gson().newBuilder().serializeNulls().create().toJson(o);
    }

    public static Map<String, Object> getUserInfo(
            @NonNull WireMockExtension wireMock, @Nullable Object groups, boolean withAvatar) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("sub", TEST_USER_USERNAME);
        userInfo.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        userInfo.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        if (groups != null) {
            userInfo.put(GROUPS_FIELD, groups);
        }
        if (withAvatar) {
            userInfo.put("picture", wireMock.url("/my-avatar.png"));
        }
        return userInfo;
    }

    public static KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public static @NonNull Map<String, Object> setUpKeyValuesWithGroup() {
        return setUpKeyValuesWithGroup(TEST_USER_GROUPS);
    }

    public static @NonNull Map<String, Object> setUpKeyValuesWithGroup(String[] groups) {
        var keyValues = setUpKeyValuesNoGroup();
        keyValues.put(GROUPS_FIELD, groups);
        return keyValues;
    }

    public static @NonNull Map<String, Object> setUpKeyValuesNoGroup() {
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        return keyValues;
    }

    public static @NonNull Consumer<OicSecurityRealm> belongsToGroup(String groupName) {
        return sc -> {
            sc.setTokenFieldToCheckKey("contains(groups, '" + groupName + "')");
            sc.setTokenFieldToCheckValue("true");
        };
    }

    public static @NonNull Map<String, Object> setUpKeyValuesWithGroupAndSub() {
        var keyValues = setUpKeyValuesWithGroup();
        keyValues.put("sub", TEST_USER_USERNAME);
        return keyValues;
    }

    public static @NonNull Map<String, Object> setUpKeyValuesNested() {
        return Map.of(
                "nested",
                Map.of(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS, GROUPS_FIELD, TEST_USER_GROUPS),
                FULL_NAME_FIELD,
                TEST_USER_FULL_NAME);
    }

    public static void assertTestUserEmail(User user) {
        assertEquals(
                TEST_USER_EMAIL_ADDRESS,
                user.getProperty(Mailer.UserProperty.class).getAddress(),
                "Email should be " + TEST_USER_EMAIL_ADDRESS);
    }

    public static void assertTestAvatar(User user, WireMockExtension wireMock) {
        String expectedAvatarUrl = wireMock.url("/my-avatar.png");
        OicAvatarProperty avatarProperty = user.getProperty(OicAvatarProperty.class);
        assertEquals(expectedAvatarUrl, avatarProperty.getAvatarUrl(), "Avatar url should be " + expectedAvatarUrl);
        assertEquals("OpenID Connect Avatar", avatarProperty.getDisplayName());
        assertNull(avatarProperty.getIconFileName(), "Icon filename must be null");
        String urlViaAvatarResolver = UserAvatarResolver.resolve(user, "48x48");
        assertEquals(expectedAvatarUrl, urlViaAvatarResolver, "Avatar url should be " + expectedAvatarUrl);
    }

    public static void withoutExpiresIn(Map<String, String> token) {
        token.compute("expires_in", (o, n) -> null);
    }

    public static void assertTestUserIsMemberOfTestGroups(User user) {
        assertTestUserIsMemberOfGroups(user, TEST_USER_GROUPS);
    }

    public static void assertTestUserIsMemberOfGroups(User user, String... testUserGroups) {
        for (String group : testUserGroups) {
            assertTrue(user.getAuthorities().contains(group), "User should be part of group " + group);
        }
    }

    public static void assertAnonymous(JenkinsRule.WebClient webClient) {
        assertEquals(
                Jenkins.ANONYMOUS2.getPrincipal(),
                getAuthentication(webClient).getPrincipal(),
                "Shouldn't be authenticated");
    }

    /**
     * Generate JWKS entry with public key of keyPair
     */
    public static String encodePublicKey(KeyPair keyPair) {
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
}

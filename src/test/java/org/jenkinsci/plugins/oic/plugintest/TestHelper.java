package org.jenkinsci.plugins.oic.plugintest;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.User;
import hudson.tasks.Mailer;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicCredentials;
import org.jenkinsci.plugins.oic.OicSecurityRealm;
import org.jenkinsci.plugins.oic.TestRealm;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.xml.sax.SAXException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.google.gson.JsonParser.parseString;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TestHelper {

    public static final String TEST_USER_EMAIL_ADDRESS = "test@jenkins.oic";
    public static final String TEST_USER_FULL_NAME = "Oic Test User";
    public static final String[] TEST_USER_GROUPS = new String[] {"group1", "group2"};
    public static final String TEST_USER_USERNAME = "testUser";

    public static void configureWellKnown(
            WireMockRule wireMockRule, @CheckForNull String endSessionUrl, @CheckForNull List<String> scopesSupported) {
        configureWellKnown(wireMockRule, endSessionUrl, scopesSupported, "authorization_code");
    }

    public static void configureWellKnown(
            WireMockRule wireMockRule,
            @CheckForNull String endSessionUrl,
            @CheckForNull List<String> scopesSupported,
            @CheckForNull String... grantTypesSupported) {
        // scopes_supported may not be null, but is not required to be present.
        // if present it must minimally be "openid"
        // Claims with zero elements MUST be omitted from the response.

        Map<String, Object> values = new HashMap<>(Map.of(
                "authorization_endpoint",
                "http://localhost:" + wireMockRule.port() + "/authorization",
                "token_endpoint",
                "http://localhost:" + wireMockRule.port() + "/token",
                "userinfo_endpoint",
                "http://localhost:" + wireMockRule.port() + "/userinfo",
                "jwks_uri",
                "http://localhost:" + wireMockRule.port() + "/jwks",
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
        if (grantTypesSupported != null && grantTypesSupported.length != 0) {
            values.put("grant_types_supported", grantTypesSupported);
        }

        wireMockRule.stubFor(get(urlPathEqualTo("/well.known"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withBody(toJson(values))));
    }

    public static String toJson(Object o) {
        return new Gson().newBuilder().serializeNulls().create().toJson(o);
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

    public static String createIdToken(PrivateKey privateKey, Map<String, Object> keyValues) throws Exception {
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

    public static @NonNull Consumer<OicSecurityRealm> belongsToGroup(String groupName) {
        return sc -> {
            sc.setTokenFieldToCheckKey("contains(groups, '" + groupName + "')");
            sc.setTokenFieldToCheckValue("true");
        };
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

    /**
     * Gets the authentication object from the web client.
     *
     * @return the authentication object
     */
    public static Object getPrincipal(JenkinsRule.WebClient webClient) {
        try {
            return webClient.executeOnServer(Jenkins::getAuthentication2).getPrincipal();
        } catch (Exception e) {
            // safely ignore all exceptions, the method never throws anything
            return null;
        }
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

    public static Map<String, Object> getUserInfo(@Nullable Object groups) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("sub", TEST_USER_USERNAME);
        userInfo.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        userInfo.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        if (groups != null) {
            userInfo.put(GROUPS_FIELD, groups);
        }
        return userInfo;
    }

    public static void browseLoginPage(JenkinsRule.WebClient webClient, Jenkins jenkins)
            throws IOException, SAXException {
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());
    }

    public static void configureTestRealm(
            WireMockRule wireMockRule, Jenkins jenkins, @NonNull Consumer<OicSecurityRealm> consumer) throws Exception {
        var securityRealm = new TestRealm(wireMockRule);
        consumer.accept(securityRealm);
        jenkins.setSecurityRealm(securityRealm);
    }

    public static void assertTestUserIsMemberOfTestGroups(User user) {
        assertTestUserIsMemberOfGroups(user, TestHelper.TEST_USER_GROUPS);
    }

    public static void assertTestUserIsMemberOfGroups(User user, String... testUserGroups) {
        for (String group : testUserGroups) {
            assertTrue(
                    "User should be part of group " + group,
                    user.getAuthorities().contains(group));
        }
    }

    public static void assertAnonymous(JenkinsRule.WebClient webClient) {
        assertEquals(
                "Shouldn't be authenticated", Jenkins.ANONYMOUS2.getPrincipal(), TestHelper.getPrincipal(webClient));
    }

    public static @Nullable User toUser(Authentication authentication) {
        return User.get(String.valueOf(authentication.getPrincipal()), false, Map.of());
    }

    public static void withoutRefreshToken(Map<String, String> token) {
        token.compute("refresh_token", (o, n) -> null);
    }

    public static void withoutExpiresIn(Map<String, String> token) {
        token.compute("expires_in", (o, n) -> null);
    }

    public static String createUserInfoJWT(PrivateKey privateKey, String userInfo) throws Exception {

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

    public static void assertTestUserEmail(User user) {
        assertEquals(
                "Email should be " + TEST_USER_EMAIL_ADDRESS,
                TEST_USER_EMAIL_ADDRESS,
                user.getProperty(Mailer.UserProperty.class).getAddress());
    }

    @NonNull
    public static User assertTestUser(JenkinsRule.WebClient webClient) {
        Authentication authentication = getAuthentication(webClient);
        assertNotNull("Authentication should not be null", authentication);
        assertEquals("Should be logged-in as " + TEST_USER_USERNAME, TEST_USER_USERNAME, authentication.getPrincipal());
        User user = toUser(authentication);
        assertNotNull("User should not be null", user);
        assertEquals("Full name should be " + TEST_USER_FULL_NAME, TEST_USER_FULL_NAME, user.getFullName());
        return user;
    }

    public static HttpResponse<String> getPageWithGet(JenkinsRule jenkinsRule, String url)
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
     */
    public static HttpResponse<String> getPageWithGet(JenkinsRule jenkinsRule, String user, String token, String url)
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

    public static void expire(JenkinsRule.WebClient webClient) throws Exception {
        webClient.executeOnServer(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User user = User.get2(authentication);
            if (user == null) {
                return null;
            }
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
}

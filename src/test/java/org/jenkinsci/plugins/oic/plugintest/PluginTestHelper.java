package org.jenkinsci.plugins.oic.plugintest;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.google.gson.JsonParser.parseString;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.FULL_NAME_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_EMAIL_ADDRESS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_FULL_NAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_GROUPS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.User;
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
import java.util.Base64;
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

public class PluginTestHelper {

    public static @NonNull Map<String, Object> setUpKeyValuesWithGroup() {
        return setUpKeyValuesWithGroup(TEST_USER_GROUPS);
    }

    public static @NonNull Map<String, Object> setUpKeyValuesWithGroup(String[] groups) {
        var keyValues = setUpKeyValuesNoGroup();
        keyValues.put(GROUPS_FIELD, groups);
        return keyValues;
    }

    public static void configureTestRealm(
            @NonNull WireMockExtension wireMock, @NonNull Jenkins jenkins, @NonNull Consumer<OicSecurityRealm> consumer)
            throws Exception {
        var securityRealm = new TestRealm(wireMock);
        consumer.accept(securityRealm);
        jenkins.setSecurityRealm(securityRealm);
    }

    public static void browseLoginPage(@NonNull JenkinsRule.WebClient webClient, @NonNull Jenkins jenkins)
            throws IOException, SAXException {
        webClient.goTo(jenkins.getSecurityRealm().getLoginUrl());
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

    public static void configureWellKnown(
            @NonNull WireMockExtension wireMock,
            @CheckForNull String endSessionUrl,
            @CheckForNull List<String> scopesSupported) {
        configureWellKnown(wireMock, endSessionUrl, scopesSupported, "authorization_code");
    }

    public static @NonNull Map<String, Object> setUpKeyValuesNoGroup() {
        Map<String, Object> keyValues = new HashMap<>();
        keyValues.put(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS);
        keyValues.put(FULL_NAME_FIELD, TEST_USER_FULL_NAME);
        return keyValues;
    }

    public static void expire(JenkinsRule.WebClient webClient) throws Exception {
        webClient.executeOnServer(() -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            User user = User.get2(authentication);
            assertNotNull(user);
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

    public static void configureWellKnown(
            @NonNull WireMockExtension wireMock,
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
        assertNotNull(grantTypesSupported);
        if (grantTypesSupported.length != 0) {
            values.put("grant_types_supported", grantTypesSupported);
        }

        wireMock.stubFor(get(urlPathEqualTo("/well.known"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withBody(toJson(values))));
    }

    public static void withoutRefreshToken(Map<String, String> token) {
        token.compute("refresh_token", (o, n) -> null);
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
    public static @NonNull Authentication getAuthentication(@NonNull JenkinsRule.WebClient webClient) {
        Authentication authentication = null;
        try {
            authentication = webClient.executeOnServer(Jenkins::getAuthentication2);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        assertNotNull(authentication);
        return authentication;
    }

    public static @NonNull Map<String, Object> setUpKeyValuesWithGroupAndSub() {
        var keyValues = setUpKeyValuesWithGroup();
        keyValues.put("sub", TEST_USER_USERNAME);
        return keyValues;
    }

    public static @Nullable User toUser(Authentication authentication) {
        return User.get(String.valueOf(authentication.getPrincipal()), false, Map.of());
    }

    public static @NonNull Map<String, Object> setUpKeyValuesNested() {
        return Map.of(
                "nested",
                Map.of(EMAIL_FIELD, TEST_USER_EMAIL_ADDRESS, GROUPS_FIELD, TEST_USER_GROUPS),
                FULL_NAME_FIELD,
                TEST_USER_FULL_NAME);
    }

    public static @NonNull Consumer<OicSecurityRealm> belongsToGroup(String groupName) {
        return sc -> {
            sc.setTokenFieldToCheckKey("contains(groups, '" + groupName + "')");
            sc.setTokenFieldToCheckValue("true");
        };
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

    public static String toJson(Object o) {
        return new Gson().newBuilder().serializeNulls().create().toJson(o);
    }

    public static KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}

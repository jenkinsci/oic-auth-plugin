package org.jenkinsci.plugins.oic.plugintest;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.google.gson.JsonParser.parseString;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.getUserInfo;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.toJson;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicSecurityRealm;
import org.jenkinsci.plugins.oic.TestRealm;

public class PluginTestMocks {

    public static void configureWellKnown(
            @NonNull WireMockExtension wireMock,
            @CheckForNull String endSessionUrl,
            @CheckForNull List<String> scopesSupported) {
        configureWellKnown(wireMock, endSessionUrl, scopesSupported, "authorization_code");
    }

    public static void configureWellKnown(
            @NonNull WireMockExtension wireMock,
            @CheckForNull String endSessionUrl,
            @CheckForNull List<String> scopesSupported,
            @CheckForNull String... grantTypesSupported) {
        // scopes_supported may not be null, but is not required to be present.
        // if present it must minimally be "openid"
        // Claims with zero elements MUST be omitted from the response.

        int port = wireMock.getPort();
        Map<String, Object> values = new HashMap<>(Map.of(
                "authorization_endpoint",
                "http://localhost:" + port + "/authorization",
                "token_endpoint",
                "http://localhost:" + port + "/token",
                "userinfo_endpoint",
                "http://localhost:" + port + "/userinfo",
                "jwks_uri",
                "http://localhost:" + port + "/jwks",
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

        wireMock.stubFor(get(urlPathEqualTo("/well.known"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withBody(toJson(values))));
    }

    public static void configureTestRealm(
            @NonNull WireMockExtension wireMock, @NonNull Jenkins jenkins, @NonNull Consumer<OicSecurityRealm> consumer)
            throws Exception {
        var securityRealm = new TestRealm(wireMock);
        consumer.accept(securityRealm);
        jenkins.setSecurityRealm(securityRealm);
    }

    public static void mockAuthorizationRedirectsToFinishLogin(
            @NonNull WireMockExtension wireMock, @NonNull Jenkins jenkins) {
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

    @SafeVarargs
    public static void mockTokenReturnsIdTokenWithGroup(
            @NonNull WireMockExtension wireMock, @CheckForNull Consumer<Map<String, String>>... tokenAcceptors)
            throws Exception {
        var keyPair = PluginTestHelper.createKeyPair();
        mockTokenReturnsIdToken(
                wireMock,
                createIdToken(keyPair.getPrivate(), PluginTestHelper.setUpKeyValuesWithGroup()),
                tokenAcceptors);
    }

    public static void mockTokenReturnsIdTokenWithGroup(@NonNull WireMockExtension wireMock) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, PluginTestHelper.setUpKeyValuesWithGroup());
    }

    public static void mockTokenReturnsIdTokenWithValues(
            @NonNull WireMockExtension wireMock, Map<String, Object> keyValues) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, keyValues, PluginTestHelper.createKeyPair());
    }

    @SafeVarargs
    public static void mockTokenReturnsIdToken(
            @NonNull WireMockExtension wireMock,
            @CheckForNull String idToken,
            @CheckForNull Consumer<Map<String, String>>... tokenAcceptors) {
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

    public static void mockTokenReturnsIdTokenWithoutValues(@NonNull WireMockExtension wireMock) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, Map.of());
    }

    public static void mockTokenReturnsIdTokenWithoutValues(@NonNull WireMockExtension wireMock, KeyPair keyPair)
            throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, Map.of(), keyPair);
    }

    public static void mockUserInfoWithTestGroups(@NonNull WireMockExtension wireMock) {
        mockUserInfoWithGroups(wireMock, PluginTestHelper.TEST_USER_GROUPS);
    }

    public static void mockUserInfoWithGroups(@NonNull WireMockExtension wireMock, @Nullable Object groups) {
        mockUserInfo(wireMock, PluginTestHelper.getUserInfo(wireMock, groups, false));
    }

    public static void mockUserInfoWithAvatar(@NonNull WireMockExtension wireMock) {
        mockUserInfo(wireMock, PluginTestHelper.getUserInfo(wireMock, null, true));
    }

    public static void mockUserInfo(@NonNull WireMockExtension wireMock, Map<String, Object> userInfo) {
        wireMock.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(toJson(userInfo))));
    }

    public static void mockUserInfoJwtWithTestGroups(
            @NonNull WireMockExtension wireMock, KeyPair keyPair, Object testUserGroups) throws Exception {
        wireMock.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/jwt")
                        .withBody(createUserInfoJWT(
                                keyPair.getPrivate(), toJson(getUserInfo(wireMock, testUserGroups, false))))));
    }

    private static void mockTokenReturnsIdTokenWithValues(
            @NonNull WireMockExtension wireMock, Map<String, Object> keyValues, KeyPair keyPair) throws Exception {
        mockTokenReturnsIdToken(wireMock, createIdToken(keyPair.getPrivate(), keyValues));
    }

    private static void mockTokenReturnsIdToken(@NonNull WireMockExtension wireMock, @CheckForNull String idToken) {
        mockTokenReturnsIdToken(wireMock, idToken, new Consumer[0]);
    }

    private static String createIdToken(PrivateKey privateKey, Map<String, Object> keyValues) throws Exception {
        JsonWebSignature.Header header =
                new JsonWebSignature.Header().setAlgorithm("RS256").setKeyId("jwks_key_id");
        long now = Clock.systemUTC().millis() / 1000;
        IdToken.Payload payload = new IdToken.Payload()
                .setExpirationTimeSeconds(now + 60L)
                .setIssuedAtTimeSeconds(now)
                .setIssuer(TestRealm.ISSUER)
                .setSubject(PluginTestHelper.TEST_USER_USERNAME)
                .setAudience(Collections.singletonList(TestRealm.CLIENT_ID))
                .setNonce("nonce");
        for (Map.Entry<String, Object> keyValue : keyValues.entrySet()) {
            payload.set(keyValue.getKey(), keyValue.getValue());
        }

        return JsonWebSignature.signUsingRsaSha256(privateKey, GsonFactory.getDefaultInstance(), header, payload);
    }

    private static String createUserInfoJWT(PrivateKey privateKey, String userInfo) throws Exception {

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
}

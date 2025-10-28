package org.jenkinsci.plugins.oic.plugintest;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_GROUPS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.createKeyPair;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.createUserInfoJWT;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.getUserInfo;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.setUpKeyValuesWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.toJson;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.TestRealm;

public class PluginTestMocks {
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

    public static void mockTokenReturnsIdTokenWithGroup(@NonNull WireMockExtension wireMock) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, setUpKeyValuesWithGroup());
    }

    public static void mockTokenReturnsIdTokenWithoutValues(@NonNull WireMockExtension wireMock) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, Map.of());
    }

    public static void mockUserInfoWithAvatar(@NonNull WireMockExtension wireMock) {
        mockUserInfo(wireMock, getUserInfo(wireMock, null, true));
    }

    public static void mockUserInfoWithTestGroups(@NonNull WireMockExtension wireMock) {
        mockUserInfoWithGroups(wireMock, TEST_USER_GROUPS);
    }

    public static void mockUserInfoWithGroups(@NonNull WireMockExtension wireMock, @Nullable Object groups) {
        mockUserInfo(wireMock, getUserInfo(wireMock, groups, false));
    }

    public static void mockTokenReturnsIdTokenWithoutValues(@NonNull WireMockExtension wireMock, KeyPair keyPair)
            throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, Map.of(), keyPair);
    }

    @SafeVarargs
    public static void mockTokenReturnsIdTokenWithGroup(
            @NonNull WireMockExtension wireMock, @CheckForNull Consumer<Map<String, String>>... tokenAcceptors)
            throws Exception {
        var keyPair = createKeyPair();
        mockTokenReturnsIdToken(
                wireMock, createIdToken(keyPair.getPrivate(), setUpKeyValuesWithGroup()), tokenAcceptors);
    }

    public static void mockTokenReturnsIdTokenWithValues(
            @NonNull WireMockExtension wireMock, Map<String, Object> keyValues) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMock, keyValues, createKeyPair());
    }

    public static void mockUserInfoJwtWithTestGroups(
            @NonNull WireMockExtension wireMock, KeyPair keyPair, Object testUserGroups) throws Exception {
        wireMock.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/jwt")
                        .withBody(createUserInfoJWT(
                                keyPair.getPrivate(), toJson(getUserInfo(wireMock, testUserGroups, false))))));
    }

    public static void mockUserInfo(@NonNull WireMockExtension wireMock, Map<String, Object> userInfo) {
        wireMock.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(toJson(userInfo))));
    }

    public static void mockTokenReturnsIdToken(@NonNull WireMockExtension wireMock, @CheckForNull String idToken) {
        mockTokenReturnsIdToken(wireMock, idToken, new Consumer[0]);
    }

    public static void mockTokenReturnsIdTokenWithValues(
            @NonNull WireMockExtension wireMock, Map<String, Object> keyValues, KeyPair keyPair) throws Exception {
        mockTokenReturnsIdToken(wireMock, createIdToken(keyPair.getPrivate(), keyValues));
    }

    // ---- PRIVATE

    @SafeVarargs
    private static void mockTokenReturnsIdToken(
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

    private static String createIdToken(PrivateKey privateKey, Map<String, Object> keyValues) throws Exception {
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
}

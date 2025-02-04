package org.jenkinsci.plugins.oic.plugintest;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import jenkins.model.Jenkins;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

public class Mocks {

    public static void mockAuthorizationRedirectsToFinishLogin(WireMockRule wireMockRule, Jenkins jenkins) {
        wireMockRule.stubFor(get(urlPathEqualTo("/authorization"))
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
            WireMockRule wireMockRule, @CheckForNull Consumer<Map<String, String>>... tokenAcceptors) throws Exception {
        var keyPair = TestHelper.createKeyPair();
        mockTokenReturnsIdToken(
                wireMockRule,
                TestHelper.createIdToken(keyPair.getPrivate(), TestHelper.setUpKeyValuesWithGroup()),
                tokenAcceptors);
    }

    public static void mockTokenReturnsIdToken(WireMockRule wireMockRule, @CheckForNull String idToken) {
        mockTokenReturnsIdToken(wireMockRule, idToken, new Consumer[0]);
    }

    @SafeVarargs
    public static void mockTokenReturnsIdToken(
            WireMockRule wireMockRule,
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
        wireMockRule.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(TestHelper.toJson(token))));
    }

    public static void mockTokenReturnsIdTokenWithGroup(WireMockRule wireMockRule) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMockRule, TestHelper.setUpKeyValuesWithGroup());
    }

    public static void mockUserInfoWithTestGroups(WireMockRule wireMockRule) {
        mockUserInfoWithGroups(wireMockRule, TestHelper.TEST_USER_GROUPS);
    }

    public static void mockUserInfoWithGroups(WireMockRule wireMockRule, @Nullable Object groups) {
        mockUserInfo(wireMockRule, TestHelper.getUserInfo(groups));
    }

    public static void mockUserInfoJwtWithTestGroups(WireMockRule wireMockRule, KeyPair keyPair, Object testUserGroups)
            throws Exception {
        wireMockRule.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/jwt")
                        .withBody(TestHelper.createUserInfoJWT(
                                keyPair.getPrivate(), TestHelper.toJson(TestHelper.getUserInfo(testUserGroups))))));
    }

    public static void mockUserInfo(WireMockRule wireMockRule, Map<String, Object> userInfo) {
        wireMockRule.stubFor(get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(TestHelper.toJson(userInfo))));
    }

    public static void mockTokenReturnsIdTokenWithoutValues(WireMockRule wireMockRule) throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMockRule, Map.of());
    }

    public static void mockTokenReturnsIdTokenWithoutValues(WireMockRule wireMockRule, KeyPair keyPair)
            throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMockRule, Map.of(), keyPair);
    }

    public static void mockTokenReturnsIdTokenWithValues(WireMockRule wireMockRule, Map<String, Object> keyValues)
            throws Exception {
        mockTokenReturnsIdTokenWithValues(wireMockRule, keyValues, TestHelper.createKeyPair());
    }

    public static void mockTokenReturnsIdTokenWithValues(
            WireMockRule wireMockRule, Map<String, Object> keyValues, KeyPair keyPair) throws Exception {
        mockTokenReturnsIdToken(wireMockRule, TestHelper.createIdToken(keyPair.getPrivate(), keyValues));
    }
}

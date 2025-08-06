package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import hudson.model.User;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.jenkinsci.plugins.oic.TestRealm.Builder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.MockedStatic;

public class OicSecurityRealmBearerTokenTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort().http2TlsDisabled(true))
            .build();

    private ECKey jwk;

    @BeforeEach
    void setup() throws Exception {
        this.jwk = setupJWK();
    }

    @Test
    void validJWTToken_SHOULD_BeAccepted() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(true)));
    }

    @Test
    void invalidJWTToken_SHOULD_BeRejected() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        MatcherAssert.assertThat(
                realm.attemptBearerToken(
                        new MockHttpServletRequest(Map.of("Authorization", "Bearer " + "not-a-jwt-token"))),
                Matchers.is(Optional.of(false)));
    }

    @Test
    void JWTTokenWithMissingOrInvalidAudience_SHOULD_BeRejected() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                null,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));

        jwt = createSignedJWT(
                TestRealm.ISSUER,
                "not-jenkins",
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));
    }

    @Test
    void JWTTokenWithMissingOrWrongIssuer_SHOULD_BeRejected() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                null,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));

        jwt = createSignedJWT(
                "not-the-issuer",
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));
    }

    @Test
    void JWTTokenWithMissingUsername_SHOULD_BeRejected() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                null,
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));
    }

    @Test
    void JWTTokenWithMissingGroups_SHOULD_BeAccepted() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                null,
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(true)));
    }

    @Test
    void expiredJWTToken_SHOULD_BeRejected() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().minusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));
    }

    @Test
    void expiredJWTToken_SHOULD_BeAccepted_WHEN_TokenExpirationIsDisabled() throws Exception {
        final TestRealm realm =
                defaultTestRealm().WithDisableTokenExpiration(true).build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().minusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(true)));
    }

    @Test
    void signedJWTToken_SHOULD_BeRejected_WHEN_SignatureDoesNotMatch() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));

        // tamper with jwt payload: Replace Alice with Bob to "steal" their identity
        String[] jwtParts = jwt.split("\\.");
        jwtParts[1] = new String(Base64.getUrlDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8);
        jwtParts[1] = jwtParts[1].replace("Alice", "Bob");
        jwtParts[1] =
                Base64.getUrlEncoder().withoutPadding().encodeToString(jwtParts[1].getBytes(StandardCharsets.UTF_8));
        jwt = Arrays.stream(jwtParts).collect(Collectors.joining("."));

        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));
    }

    @Test
    void unsignedJWTToken_SHOULD_BeRejected() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createUnsignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(false)));
    }

    @Test
    void unsignedJWTToken_SHOULD_BeAccepted_WHEN_TokenVerificationIsDisabled() throws Exception {
        final TestRealm realm =
                defaultTestRealm().WithDisableTokenValidation(true).build();

        String jwt = createUnsignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));
        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt))),
                Matchers.is(Optional.of(true)));
    }

    @Test
    void bearerTokenLogin_SHOULD_NotBeResponsible_WHEN_NoBearerAuthHeaderIsUsed() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        MatcherAssert.assertThat(
                realm.attemptBearerToken(new MockHttpServletRequest(Map.of("Authorization", "Basic abcdef"))),
                Matchers.is(Optional.empty()));
    }

    @Test
    void bearerTokenLogin_SHOULD_TakePrecedenceOverUserChecks() throws Exception {
        final TestRealm realm = defaultTestRealm().build();

        String jwt = createSignedJWT(
                TestRealm.ISSUER,
                TestRealm.CLIENT_ID,
                "Alice",
                List.of("group1"),
                Instant.now().plusSeconds(120));

        try (MockedStatic<User> userMocked = mockStatic(User.class)) {
            userMocked.when(() -> User.get2(any())).thenReturn(null);

            // valid token should still be accepted
            MatcherAssert.assertThat(
                    realm.validateAuthentication(
                            new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt)), null),
                    Matchers.is(true));

            // invalid token should still be rejected, no matter whether User.get2(...) was null
            jwt = createSignedJWT(
                    TestRealm.ISSUER,
                    TestRealm.CLIENT_ID,
                    "Alice",
                    List.of("group1"),
                    Instant.now().minusSeconds(120));
            MatcherAssert.assertThat(
                    realm.validateAuthentication(
                            new MockHttpServletRequest(Map.of("Authorization", "Bearer " + jwt)), null),
                    Matchers.is(false));
        }
    }

    private ECKey setupJWK() throws Exception {
        var jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("123")
                .generate();

        var jwkBody =
                """
                {
                  "keys": [
                    %s
                  ]
                }
                """
                        .formatted(jwk.toPublicJWK().toJSONString());
        wireMock.stubFor(get(urlPathEqualTo("/jwk"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=utf-8")
                        .withBody(jwkBody)));
        return jwk;
    }

    private Builder defaultTestRealm() throws IOException {
        return new TestRealm.Builder(wireMock)
                .WithAllowJWTBearerTokenAccess(true)
                        .WithJwksServerUrl(wireMock.url("/jwk"))
                        .WithDisableTokenValidation(false);
    }

    private String createSignedJWT(
            String issuer, String audience, String subject, List<String> groups, Instant expiration) throws Exception {

        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .keyID(jwk.getKeyID())
                .build();

        var payload = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(subject)
                .expirationTime(Date.from(expiration))
                .claim(TestRealm.GROUPS_FIELD, groups)
                .build();

        var signedJWT = new SignedJWT(header, payload);
        signedJWT.sign(new ECDSASigner(jwk.toECPrivateKey()));
        return signedJWT.serialize();
    }

    private String createUnsignedJWT(
            String issuer, String audience, String subject, List<String> groups, Instant expiration) throws Exception {

        var header = new PlainHeader.Builder().type(JOSEObjectType.JWT).build();

        var payload = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(subject)
                .expirationTime(Date.from(expiration))
                .claim(TestRealm.GROUPS_FIELD, groups)
                .build();

        return new PlainJWT(header, payload).serialize();
    }
}

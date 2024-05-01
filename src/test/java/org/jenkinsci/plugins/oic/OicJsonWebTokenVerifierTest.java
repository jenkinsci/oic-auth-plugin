/*
 * The MIT License
 *
 * Copyright (c) 2024 JenkinsCI oic-auth-plugin developers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.util.Base64;
import com.google.api.client.util.Clock;
import com.google.api.client.util.SecurityUtils;
import com.google.api.client.util.StringUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OicJsonWebTokenVerifierTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(), true);

    KeyPair keyPair = createKeyPair();

    @Test
    public void testVanillaCaseShouldbeSuccessfulAndVerifySignature() throws Exception {
        wireMockRule.resetAll();
        IdToken idtoken = createIdToken(keyPair.getPrivate(), new HashMap<>());
        OicJsonWebTokenVerifier verifier = new OicJsonWebTokenVerifier(
                "http://localhost:" + wireMockRule.port() + "/jwks",
                new OicJsonWebTokenVerifier.Builder()
                );
        assertTrue(verifier.isJwksServerUrlAvailable());

        wireMockRule.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\":[{"+encodePublicKey(keyPair)+
                            ",\"alg\":\"RS256\""+
                            ",\"use\":\"sig\",\"kid\":\"jwks_key_id\""+
                            "}]}")));

        assertTrue(verifier.verifyIdToken(idtoken));
        assertTrue(verifier.isJwksServerUrlAvailable());
    }

    @Test
    public void tesNoJWKSURIShouldBeSuccessfulAndNeverVerifySignature() throws Exception {
        IdToken idtoken = createIdToken(keyPair.getPrivate(), new HashMap<>());
        OicJsonWebTokenVerifier verifier = new OicJsonWebTokenVerifier(
                null,
                new OicJsonWebTokenVerifier.Builder()
                );
        assertFalse(verifier.isJwksServerUrlAvailable());

        assertTrue(verifier.verifyIdToken(idtoken));
    }

    @Test
    public void testCannotGetJWKSURIShouldbeSuccessfulAndDisableSignature() throws Exception {
        wireMockRule.resetAll();
        IdToken idtoken = createIdToken(keyPair.getPrivate(), new HashMap<>());
        OicJsonWebTokenVerifier verifier = new OicJsonWebTokenVerifier(
                "http://localhost:" + wireMockRule.port() + "/jwks",
                new OicJsonWebTokenVerifier.Builder()
                );
        assertTrue(verifier.isJwksServerUrlAvailable());

        wireMockRule.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse().withStatus(404)));

        assertTrue(verifier.verifyIdToken(idtoken));
        assertFalse(verifier.isJwksServerUrlAvailable());
    }

    @Test
    public void testMissingAlgShouldbeSuccessfulAndDisableSignature() throws Exception {
        wireMockRule.resetAll();
        IdToken idtoken = createIdToken(keyPair.getPrivate(), new HashMap<>());
        OicJsonWebTokenVerifier verifier = new OicJsonWebTokenVerifier(
                "http://localhost:" + wireMockRule.port() + "/jwks",
                new OicJsonWebTokenVerifier.Builder()
                );
        assertTrue(verifier.isJwksServerUrlAvailable());

        wireMockRule.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\":[{"+encodePublicKey(keyPair)+
                            ",\"use\":\"sig\",\"kid\":\"jwks_key_id\""+
                            "}]}")));

        assertTrue(verifier.verifyIdToken(idtoken));
        assertFalse(verifier.isJwksServerUrlAvailable());
    }

    @Test
    public void testUnknownAlgShouldbeSuccessfulAndDisableSignature() throws Exception {
        wireMockRule.resetAll();
        IdToken idtoken = createIdToken(keyPair.getPrivate(), new HashMap<>());
        OicJsonWebTokenVerifier verifier = new OicJsonWebTokenVerifier(
                "http://localhost:" + wireMockRule.port() + "/jwks",
                new OicJsonWebTokenVerifier.Builder()
                );
        assertTrue(verifier.isJwksServerUrlAvailable());

        wireMockRule.stubFor(get(urlPathEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\":[{"+encodePublicKey(keyPair)+
                            ",\"alg\":\"RSA-OAEP\""+
                            ",\"use\":\"sig\",\"kid\":\"jwks_key_id\""+
                            "}]}")));

        assertTrue(verifier.verifyIdToken(idtoken));
        assertFalse(verifier.isJwksServerUrlAvailable());
    }

    static private KeyPair createKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            /* should not happen */
        }
        return null;
    }

    private IdToken createIdToken(PrivateKey privateKey, Map<String, Object> keyValues) throws Exception {
        JsonWebSignature.Header header = new JsonWebSignature.Header()
            .setAlgorithm("RS256")
            .setKeyId("jwks_key_id");
        long now = (long)(Clock.SYSTEM.currentTimeMillis()/1000);
        IdToken.Payload payload = new IdToken.Payload()
            .setExpirationTimeSeconds(now + 60L)
            .setIssuedAtTimeSeconds(now)
            .setIssuer("issuer")
            .setSubject("sub")
            .setAudience(Collections.singletonList("clientId"))
            .setNonce("nonce");
        for (Map.Entry<String, Object> keyValue : keyValues.entrySet()) {
            payload.set(keyValue.getKey(), keyValue.getValue());
        }

        JsonFactory jsonFactory = GsonFactory.getDefaultInstance();
        String content =
            Base64.encodeBase64URLSafeString(jsonFactory.toByteArray(header))
            + "."
            + Base64.encodeBase64URLSafeString(jsonFactory.toByteArray(payload));
        byte[] contentBytes = StringUtils.getBytesUtf8(content);
        byte[] signature =
            SecurityUtils.sign(
                    SecurityUtils.getSha256WithRsaSignatureAlgorithm(), privateKey, contentBytes);
        return new IdToken(header, payload, signature, contentBytes);
    }

    /** Generate JWKS entry with public key of keyPair */
    String encodePublicKey(KeyPair keyPair) {
        final RSAPublicKey rsaPKey = (RSAPublicKey)(keyPair.getPublic());
        return "\"n\":\"" +
            Base64.encodeBase64String(rsaPKey.getModulus().toByteArray()) +
            "\",\"e\":\"" +
            Base64.encodeBase64String(rsaPKey.getPublicExponent().toByteArray()) +
            "\",\"kty\":\"RSA\"";
    }
}

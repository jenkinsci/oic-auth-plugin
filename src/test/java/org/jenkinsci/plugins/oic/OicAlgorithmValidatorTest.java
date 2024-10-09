package org.jenkinsci.plugins.oic;

import jenkins.security.FIPS140;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

class OicAlgorithmValidatorTest {

    private MockedStatic<FIPS140> fips140Mock;

    @BeforeEach
    void setUp() {
        fips140Mock = mockStatic(FIPS140.class);
    }

    @Test
    void isJwsAlgorithmFipsCompliant() {
        fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
        assertTrue(OicAlgorithmValidator.isJwsAlgorithmFipsNonCompliant(""));
        assertTrue(OicAlgorithmValidator.isJwsAlgorithmFipsNonCompliant(" "));
        assertTrue(OicAlgorithmValidator.isJwsAlgorithmFipsNonCompliant("invalid-algo"));

        String[] validAlgoArray = {
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES256K", "ES384", "ES512", "PS256", "PS384",
            "PS512"
        };
        for (String algo : validAlgoArray) {
            assertFalse(OicAlgorithmValidator.isJwsAlgorithmFipsNonCompliant(algo));
        }
        assertTrue(OicAlgorithmValidator.isJwsAlgorithmFipsNonCompliant("EdDSA"));
        assertTrue(OicAlgorithmValidator.isJwsAlgorithmFipsNonCompliant("Ed25519"));
        assertTrue(OicAlgorithmValidator.isJwsAlgorithmFipsNonCompliant("Ed448"));
    }
}

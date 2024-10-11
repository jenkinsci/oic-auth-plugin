package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.JWSAlgorithm;
import jenkins.security.FIPS140;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

class OicAlgorithmValidatorFIPS140Test {

    private MockedStatic<FIPS140> fips140Mock;

    @BeforeEach
    void setUp() {
        fips140Mock = mockStatic(FIPS140.class);
    }

    @Test
    void isJwsAlgorithmFipsCompliant() {
        fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
        assertFalse(OicAlgorithmValidatorFIPS140.isJwsAlgorithmFipsCompliant(new JWSAlgorithm("")));
        assertFalse(OicAlgorithmValidatorFIPS140.isJwsAlgorithmFipsCompliant(new JWSAlgorithm(" ")));
        assertFalse(OicAlgorithmValidatorFIPS140.isJwsAlgorithmFipsCompliant(new JWSAlgorithm("invalid-algo")));

        String[] validAlgoArray = {
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES256K", "ES384", "ES512", "PS256", "PS384",
            "PS512"
        };
        for (String algo : validAlgoArray) {
            assertTrue(OicAlgorithmValidatorFIPS140.isJwsAlgorithmFipsCompliant(new JWSAlgorithm(algo)));
        }
        assertFalse(OicAlgorithmValidatorFIPS140.isJwsAlgorithmFipsCompliant(new JWSAlgorithm("EdDSA")));
        assertFalse(OicAlgorithmValidatorFIPS140.isJwsAlgorithmFipsCompliant(new JWSAlgorithm("Ed25519")));
        assertFalse(OicAlgorithmValidatorFIPS140.isJwsAlgorithmFipsCompliant(new JWSAlgorithm("Ed448")));
    }
}

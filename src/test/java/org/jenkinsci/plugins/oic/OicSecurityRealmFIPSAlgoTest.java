package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import jenkins.security.FIPS140;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

class OicSecurityRealmFIPSAlgoTest {

    @Test
    void doCheckAlgorithmFilteredNotInFipsMode() throws Exception {
        try (MockedStatic<FIPS140> fips140Mocked = mockStatic(FIPS140.class)) {
            fips140Mocked.when(FIPS140::useCompliantAlgorithms).thenReturn(false);

            OIDCProviderMetadata oidcProviderMetadata = generateProviderMetadata();

            OicSecurityRealm mocked = mock(OicSecurityRealm.class);
            doCallRealMethod().when(mocked).filterNonFIPS140CompliantAlgorithms(any());

            mocked.filterNonFIPS140CompliantAlgorithms(oidcProviderMetadata);

            /*
            Original List: "PS384", "RS384", "EdDSA", "ES384", "HS256", "HS512", "ES256", "RS256", "HS384", "ES512",
                           "PS256", "PS512", "RS512"
            Non FIPS: "EdDSA"
             */
            assertThat(
                    "EdDSA is non compliant, but we are not in FIPS mode",
                    oidcProviderMetadata.getIDTokenJWSAlgs(),
                    containsInAnyOrder(
                            JWSAlgorithm.HS256,
                            JWSAlgorithm.HS384,
                            JWSAlgorithm.HS512,
                            JWSAlgorithm.RS256,
                            JWSAlgorithm.RS384,
                            JWSAlgorithm.RS512,
                            JWSAlgorithm.ES256,
                            JWSAlgorithm.ES384,
                            JWSAlgorithm.ES512,
                            JWSAlgorithm.PS256,
                            JWSAlgorithm.PS384,
                            JWSAlgorithm.PS512,
                            JWSAlgorithm.EdDSA));
            /*
            Original List: "RSA-OAEP", "RSA-OAEP-256", "RSA1_5"
            Non FIPS: "RSA1_5"
             */
            assertThat(
                    "RSA1_5 is non compliant, but we are not in FIPS mode",
                    oidcProviderMetadata.getIDTokenJWEAlgs(),
                    containsInAnyOrder(JWEAlgorithm.RSA_OAEP, JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA1_5));

            /*
            Original List: "A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "XC20P"
            Non FIPS: "XC20P"
             */
            assertThat(
                    "XC20P is non compliant, but we are not in FIPS mode",
                    oidcProviderMetadata.getIDTokenJWEEncs(),
                    containsInAnyOrder(
                            EncryptionMethod.A256GCM,
                            EncryptionMethod.A192GCM,
                            EncryptionMethod.A128GCM,
                            EncryptionMethod.A128CBC_HS256,
                            EncryptionMethod.A192CBC_HS384,
                            EncryptionMethod.A256CBC_HS512,
                            EncryptionMethod.XC20P));
        }
    }

    @Test
    void doCheckAlgorithmFilteredInFipsMode() throws Exception {
        try (MockedStatic<FIPS140> fips140Mocked = mockStatic(FIPS140.class)) {
            fips140Mocked.when(FIPS140::useCompliantAlgorithms).thenReturn(true);

            OIDCProviderMetadata oidcProviderMetadata = generateProviderMetadata();

            OicSecurityRealm mocked = mock(OicSecurityRealm.class);
            doCallRealMethod().when(mocked).filterNonFIPS140CompliantAlgorithms(any());

            mocked.filterNonFIPS140CompliantAlgorithms(oidcProviderMetadata);

            /*
            Original List: "PS384", "RS384", "EdDSA", "ES384", "HS256", "HS512", "ES256", "RS256", "HS384", "ES512",
                           "PS256", "PS512", "RS512"
            Non FIPS: "EdDSA"
             */
            assertThat(
                    "EdDSA is non compliant",
                    oidcProviderMetadata.getIDTokenJWSAlgs(),
                    not(contains(JWSAlgorithm.EdDSA)));
            assertThat(
                    "Rest of algorithms are compliant",
                    oidcProviderMetadata.getIDTokenJWSAlgs(),
                    containsInAnyOrder(
                            JWSAlgorithm.HS256,
                            JWSAlgorithm.HS384,
                            JWSAlgorithm.HS512,
                            JWSAlgorithm.RS256,
                            JWSAlgorithm.RS384,
                            JWSAlgorithm.RS512,
                            JWSAlgorithm.ES256,
                            JWSAlgorithm.ES384,
                            JWSAlgorithm.ES512,
                            JWSAlgorithm.PS256,
                            JWSAlgorithm.PS384,
                            JWSAlgorithm.PS512));
            /*
            Original List: "RSA-OAEP", "RSA-OAEP-256", "RSA1_5"
            Non FIPS: "RSA1_5"
             */
            assertThat(
                    "RSA1_5 is non compliant",
                    oidcProviderMetadata.getIDTokenJWEAlgs(),
                    not(contains(JWEAlgorithm.RSA1_5)));
            assertThat(
                    "Rest of algorithms are compliant",
                    oidcProviderMetadata.getIDTokenJWEAlgs(),
                    containsInAnyOrder(JWEAlgorithm.RSA_OAEP, JWEAlgorithm.RSA_OAEP_256));

            /*
            Original List: "A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "XC20P"
            Non FIPS: "XC20P"
             */
            assertThat(
                    "XC20P is non compliant",
                    oidcProviderMetadata.getIDTokenJWEEncs(),
                    not(contains(EncryptionMethod.XC20P)));
            assertThat(
                    "Rest of algorithms are compliant",
                    oidcProviderMetadata.getIDTokenJWEEncs(),
                    containsInAnyOrder(
                            EncryptionMethod.A256GCM,
                            EncryptionMethod.A192GCM,
                            EncryptionMethod.A128GCM,
                            EncryptionMethod.A128CBC_HS256,
                            EncryptionMethod.A192CBC_HS384,
                            EncryptionMethod.A256CBC_HS512));
        }
    }

    private OIDCProviderMetadata generateProviderMetadata() throws Exception {
        File json = Paths.get(
                        "src/test/resources/org/jenkinsci/plugins/oic/OicSecurityRealmFIPSAlgoTest/metadata" + ".json")
                .toFile();
        String metadata = FileUtils.readFileToString(json, StandardCharsets.UTF_8);

        return OIDCProviderMetadata.parse(JSONObjectUtils.parse(metadata));
    }
}

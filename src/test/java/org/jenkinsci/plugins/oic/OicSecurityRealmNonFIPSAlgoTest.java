package org.jenkinsci.plugins.oic;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.IOException;
import jenkins.security.FIPS140;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.MockedStatic;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mockStatic;

public class OicSecurityRealmNonFIPSAlgoTest {

    private static MockedStatic<FIPS140> fips140Mock;

    @BeforeClass
    public static void setup() {
        fips140Mock = mockStatic(FIPS140.class);
        fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(false);
    }

    @AfterClass
    public static void breakdown() {
        fips140Mock.close();
    }

    @Test
    public void doCheckAlgorithmFilter() throws IOException, ParseException {
        OIDCProviderMetadata oidcProviderMetadata = OicSecurityRealmFIPSAlgoTest.getNonCompliantMockObject();
        oidcProviderMetadata.setClientRegistrationAuthnJWSAlgs(OicSecurityRealmFIPSAlgoTest.compliantJwsAlgo());
        oidcProviderMetadata.setDPoPJWSAlgs(OicSecurityRealmFIPSAlgoTest.compliantJwsAlgo());
        oidcProviderMetadata.setAuthorizationJWSAlgs(OicSecurityRealmFIPSAlgoTest.compliantJwsAlgo());
        oidcProviderMetadata.setAuthorizationJWEAlgs(OicSecurityRealmFIPSAlgoTest.compliantJweAlgo());
        oidcProviderMetadata.setAuthorizationJWEEncs(OicSecurityRealmFIPSAlgoTest.compliantEncryptionMethod());
        oidcProviderMetadata.setClientRegistrationAuthnJWSAlgs(OicSecurityRealmFIPSAlgoTest.compliantJwsAlgo());

        int countIDTokenJWSAlgs = oidcProviderMetadata.getIDTokenJWSAlgs().size();
        int countIDTokenJWEAlgs = oidcProviderMetadata.getIDTokenJWEAlgs().size();
        int countIDTokenEncMethod = oidcProviderMetadata.getIDTokenJWEEncs().size();
        OicSecurityRealm.filterNonCompliantAlgorithms(oidcProviderMetadata);
        assertEquals(
                countIDTokenJWSAlgs, oidcProviderMetadata.getIDTokenJWSAlgs().size());
        assertEquals(
                countIDTokenJWEAlgs, oidcProviderMetadata.getIDTokenJWEAlgs().size());
        assertEquals(
                countIDTokenEncMethod, oidcProviderMetadata.getIDTokenJWEEncs().size());
    }
}

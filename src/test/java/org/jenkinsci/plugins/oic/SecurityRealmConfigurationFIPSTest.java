package org.jenkinsci.plugins.oic;

import hudson.model.Descriptor;
import jenkins.security.FIPS140;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;

class SecurityRealmConfigurationFIPSTest {

    @Test
    void escapeHatchThrowsException() {
        try (MockedStatic<FIPS140> fips140Mocked = mockStatic(FIPS140.class)) {
            fips140Mocked.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
            assertThrows(
                    Descriptor.FormException.class,
                    () -> new OicSecurityRealm("clientId", null, null, null, null, null).setEscapeHatchEnabled(true));
        }
    }

    @Test
    void escapeHatchToFalse() throws Exception {
        OicSecurityRealm oicSecurityRealm = new OicSecurityRealm("clientId", null, null, null, null, null);
        oicSecurityRealm.setEscapeHatchEnabled(false);
        assertThat(oicSecurityRealm.isEscapeHatchEnabled(), is(false));
    }

    @Test
    void readResolve() throws Exception {
        OicSecurityRealm oicSecurityRealm = new OicSecurityRealm("clientId", null, null, null, null, null);
        oicSecurityRealm.setEscapeHatchEnabled(false);
        assertThat(oicSecurityRealm.isEscapeHatchEnabled(), is(false));
        oicSecurityRealm.readResolve();
    }

    @Test
    void readResolveIsDisableSslVerification() throws Exception {
        try (MockedStatic<FIPS140> fips140Mock = mockStatic(FIPS140.class)) {
            fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(false);
            OicSecurityRealm oicSecurityRealm = new OicSecurityRealm("clientId", null, null, Boolean.TRUE, null, null);
            oicSecurityRealm.setEscapeHatchEnabled(false);
            assertThat(oicSecurityRealm.isEscapeHatchEnabled(), is(false));

            fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
            IllegalStateException ex = assertThrows(IllegalStateException.class, oicSecurityRealm::readResolve);
            assertThat(ex.getMessage(), is(Messages.OicSecurityRealm_DisableSslVerificationFipsMode()));
        }
    }

    @Test
    void readResolveIsDisableTokenVerification() throws Exception {
        try (MockedStatic<FIPS140> fips140Mock = mockStatic(FIPS140.class)) {
            fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(false);
            OicSecurityRealm oicSecurityRealm = new OicSecurityRealm("clientId", null, null, Boolean.FALSE, null, null);
            oicSecurityRealm.setEscapeHatchEnabled(false);
            oicSecurityRealm.setDisableTokenVerification(true);
            assertThat(oicSecurityRealm.isEscapeHatchEnabled(), is(false));

            fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
            IllegalStateException ex = assertThrows(IllegalStateException.class, oicSecurityRealm::readResolve);
            assertThat(ex.getMessage(), is(Messages.OicSecurityRealm_DisableTokenVerificationFipsMode()));
        }
    }
}

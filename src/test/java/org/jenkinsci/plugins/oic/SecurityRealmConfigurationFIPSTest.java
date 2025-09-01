package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import hudson.model.Descriptor;
import jenkins.security.FIPS140;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SecurityRealmConfigurationFIPSTest {

    private static Object fipsProperty;

    @BeforeAll
    static void setUp() {
        fipsProperty = System.getProperties().setProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");
    }

    @AfterAll
    static void tearDown() {
        if (fipsProperty != null) {
            System.setProperty(FIPS140.class.getName() + ".COMPLIANCE", String.valueOf(fipsProperty));
        } else {
            System.clearProperty(FIPS140.class.getName() + ".COMPLIANCE");
        }
    }

    @Test
    void escapeHatchThrowsException() {
        assertThrows(
                Descriptor.FormException.class,
                () -> new OicSecurityRealm("clientId", null, null, null, null, null).setEscapeHatchEnabled(true));
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
}

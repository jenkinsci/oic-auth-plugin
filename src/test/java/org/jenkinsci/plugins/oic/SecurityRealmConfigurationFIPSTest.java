package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import hudson.model.Descriptor;
import hudson.util.Secret;
import jenkins.security.FIPS140;
import org.jenkinsci.plugins.oic.properties.EscapeHatch;
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
                Descriptor.FormException.class, () -> new OicSecurityRealm("clientId", null, null, null, null, null)
                        .getProperties()
                        .add(new EscapeHatch("admin", null, Secret.fromString("very-secret"))));
    }

    @Test
    void escapeHatchToFalse() throws Exception {
        OicSecurityRealm oicSecurityRealm = new OicSecurityRealm("clientId", null, null, null, null, null);
        assertThat(oicSecurityRealm.getProperties().get(EscapeHatch.class), nullValue());
    }

    @Test
    void readResolve() throws Exception {
        OicSecurityRealm oicSecurityRealm = new OicSecurityRealm("clientId", null, null, null, null, null);
        assertThat(oicSecurityRealm.getProperties().get(EscapeHatch.class), nullValue());
        oicSecurityRealm.readResolve();
        assertThat(oicSecurityRealm.getProperties().get(EscapeHatch.class), nullValue());
    }
}

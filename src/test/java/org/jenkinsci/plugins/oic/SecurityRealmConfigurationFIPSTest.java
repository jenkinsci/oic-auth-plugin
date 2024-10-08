package org.jenkinsci.plugins.oic;

import hudson.model.Descriptor;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class SecurityRealmConfigurationFIPSTest {

    @ClassRule
    public static FlagRule<String> FIPS_RULE = FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @Test(expected = Descriptor.FormException.class)
    public void escapeHatchThrowsException() throws Exception {
        new OicSecurityRealm("clientId", null, null, null).setEscapeHatchEnabled(true);
    }

    @Test
    public void escapeHatchToFalse() throws Exception {
        OicSecurityRealm oicSecurityRealm = new OicSecurityRealm("clientId", null, null, null);
        oicSecurityRealm.setEscapeHatchEnabled(false);
        assertThat(oicSecurityRealm.isEscapeHatchEnabled(), is(false));
    }
}

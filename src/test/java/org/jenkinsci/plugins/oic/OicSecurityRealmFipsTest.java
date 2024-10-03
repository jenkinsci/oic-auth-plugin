package org.jenkinsci.plugins.oic;

import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import jenkins.security.FIPS140;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.reactor.ReactorException;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class OicSecurityRealmFipsTest {

    @ClassRule
    public static FlagRule<String> fipsFlag = FlagRule.systemProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");

    @Rule
    public NonFailingOnStartupJenkinsRule j = new NonFailingOnStartupJenkinsRule();

    @Test
    @WithoutJenkins
    public void settingNonCompliantValuesNotAllowedTest() throws IOException {
        OicSecurityRealm realm = new OicSecurityRealm("clientId", Secret.fromString("secret"), null, false);
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> new OicSecurityRealm("clientId", Secret.fromString("secret"), null, true));
        assertThat(
                "Exception contains the reason",
                ex.getLocalizedMessage(),
                containsString("SSL verification can not be disabled"));
        realm.setDisableTokenVerification(false);
        ex = assertThrows(IllegalArgumentException.class, () -> realm.setDisableTokenVerification(true));
        assertThat(
                "Exception contains the reason",
                ex.getLocalizedMessage(),
                containsString("Token verification can not be disabled"));
    }

    @Test
    @WithoutJenkins
    public void validationWarnsOfInvalidValuesTest() {
        OicSecurityRealm.DescriptorImpl descriptor = new OicSecurityRealm.DescriptorImpl();
        FormValidation response = descriptor.doCheckDisableSslVerification(true);
        assertThat("Shows an error", response.kind, is(FormValidation.Kind.ERROR));
        assertThat(
                "States SSL verification can not be disabled",
                response.getMessage(),
                containsString("SSL verification can not be disabled"));
        response = descriptor.doCheckDisableSslVerification(false);
        assertThat("Validation is ok", response.kind, is(FormValidation.Kind.OK));

        response = descriptor.doCheckDisableTokenVerification(true);
        assertThat("Shows an error", response.kind, is(FormValidation.Kind.ERROR));
        assertThat(
                "States token verification can not be disabled",
                response.getMessage(),
                containsString("Token verification can not be disabled"));
        response = descriptor.doCheckDisableTokenVerification(false);
        assertThat("Validation is ok", response.kind, is(FormValidation.Kind.OK));
    }

    // This test is not strictly needed as per
    // https://github.com/jenkinsci/jep/blob/master/jep/237/README.adoc#backwards-compatibility
    // Just adding it to cover corner cases
    @Test
    @LocalData
    public void failsOnMigrationTest() {
        assertTrue("We should get a ReactorException, startup failed", j.getError() instanceof ReactorException);
    }

    // Simple JenkinsRule extension that doesn't make test fail on startup errors, so we can check the error.
    public static class NonFailingOnStartupJenkinsRule extends JenkinsRule {
        private Throwable error;

        @Override
        public void before() throws Throwable {
            try {
                super.before();
            } catch (Throwable t) {
                error = t;
            }
        }

        public Throwable getError() {
            return error;
        }
    }
}

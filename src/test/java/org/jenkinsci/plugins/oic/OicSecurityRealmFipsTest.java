package org.jenkinsci.plugins.oic;

import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import jenkins.security.FIPS140;
import org.hamcrest.Matcher;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.reactor.ReactorException;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThrows;
import static org.jvnet.hudson.test.JenkinsMatchers.hasKind;

public class OicSecurityRealmFipsTest {

    @ClassRule
    public static FlagRule<String> fipsFlag = FlagRule.systemProperty(FIPS140.class.getName() + ".COMPLIANCE", "true");

    @Rule
    public NonFailingOnStartupJenkinsRule j = new NonFailingOnStartupJenkinsRule();

    @Test
    @WithoutJenkins
    public void settingNonCompliantValuesNotAllowedTest() throws IOException, Descriptor.FormException {
        OicSecurityRealm realm = new OicSecurityRealm("clientId", Secret.fromString("secret"), null, false);
        Descriptor.FormException ex = assertThrows(
                Descriptor.FormException.class,
                () -> new OicSecurityRealm("clientId", Secret.fromString("secret"), null, true));
        assertThat(
                "Exception contains the reason",
                ex.getMessage(),
                containsString("SSL verification can not be disabled"));
        realm.setDisableTokenVerification(false);
        ex = assertThrows(Descriptor.FormException.class, () -> realm.setDisableTokenVerification(true));
        assertThat(
                "Exception contains the reason",
                ex.getMessage(),
                containsString("Token verification can not be disabled"));
    }

    @Test
    @WithoutJenkins
    public void validationWarnsOfInvalidValuesTest() {
        OicSecurityRealm.DescriptorImpl descriptor = new OicSecurityRealm.DescriptorImpl();
        FormValidation response = descriptor.doCheckDisableSslVerification(true);
        assertThat(
                "States SSL verification can not be disabled",
                response,
                allOf(
                        hasKind(FormValidation.Kind.ERROR),
                        withMessageContaining("SSL verification can not be disabled")));
        response = descriptor.doCheckDisableSslVerification(false);
        assertThat("Validation is ok", response, hasKind(FormValidation.Kind.OK));

        response = descriptor.doCheckDisableTokenVerification(true);
        assertThat(
                "States token verification can not be disabled",
                response,
                allOf(
                        hasKind(FormValidation.Kind.ERROR),
                        withMessageContaining("Token verification can not be disabled")));
        response = descriptor.doCheckDisableTokenVerification(false);
        assertThat("Validation is ok", response.kind, is(FormValidation.Kind.OK));
    }

    // This test is not strictly needed as per
    // https://github.com/jenkinsci/jep/blob/master/jep/237/README.adoc#backwards-compatibility
    // Just adding it to cover corner cases
    @Test
    @LocalData
    public void failsOnMigrationTest() {
        assertThat(
                "We should get a ReactorException, startup failed", j.getError(), instanceOf(ReactorException.class));
    }

    @Test
    @LocalData
    public void worksOnMigrationWithValidValuesTest() {
        assertThat("Instance is up and running with no errors", j.getError(), nullValue());
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

    private static Matcher<FormValidation> withMessageContaining(String message) {
        // the FormValidation message will be escaped for HTML, so we escape what we expect.
        return hasProperty("message", containsString(Util.escape(message)));
    }
}

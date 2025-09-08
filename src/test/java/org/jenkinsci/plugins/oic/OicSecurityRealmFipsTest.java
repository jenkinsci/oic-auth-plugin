package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.jvnet.hudson.test.JenkinsMatchers.hasKind;

import hudson.Util;
import hudson.init.InitMilestone;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import jenkins.security.FIPS140;
import org.hamcrest.Matcher;
import org.jenkinsci.plugins.oic.properties.AllowedTokenExpirationClockSkew;
import org.jenkinsci.plugins.oic.properties.DisableNonce;
import org.jenkinsci.plugins.oic.properties.DisableTokenVerification;
import org.jenkinsci.plugins.oic.properties.Pkce;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

@WithJenkins
class OicSecurityRealmFipsTest {

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
    @WithoutJenkins
    void settingNonCompliantValuesNotAllowedTest() throws IOException, Descriptor.FormException {
        OicSecurityRealm realm = new OicSecurityRealm("clientId", Secret.fromString("secret"), null, false, null, null);
        Exception ex = assertThrows(
                Descriptor.FormException.class,
                () -> new OicSecurityRealm("clientId", Secret.fromString("secret"), null, true, null, null));
        assertThat(
                "Exception contains the reason",
                ex.getMessage(),
                containsString("SSL verification can not be disabled"));
        realm.getProperties().removeIf(DisableTokenVerification.class::isInstance);
        ex = assertThrows(
                IllegalArgumentException.class, () -> realm.getProperties().add(new DisableTokenVerification()));
        assertThat(
                "Exception contains the reason",
                ex.getMessage(),
                containsString("Token verification can not be disabled"));
    }

    @Test
    @WithoutJenkins
    void validationWarnsOfInvalidValuesTest() {
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
    }

    @Test
    @LocalData
    void worksOnMigrationWithValidValuesTest(JenkinsRule j) {
        assertThat("Instance is up and running with no errors", j.jenkins.getInitLevel(), is(InitMilestone.COMPLETED));
        OicSecurityRealm realm = (OicSecurityRealm) j.jenkins.getSecurityRealm();
        assertThat(realm.getClientId(), is("client-id"));
        assertThat(realm.getUserNameField(), is("sub"));
        assertThat(realm.isDisableSslVerification(), is(false));
        assertThat(realm.isLogoutFromOpenidProvider(), is(false));
        assertThat(realm.getProperties().get(DisableTokenVerification.class), nullValue());
        var serverConfiguration = realm.getServerConfiguration();
        assertThat(serverConfiguration, instanceOf(OicServerWellKnownConfiguration.class));
        OicServerWellKnownConfiguration swk = (OicServerWellKnownConfiguration) serverConfiguration;
        assertThat(swk.getWellKnownOpenIDConfigurationUrl(), is("https://example.test"));
        assertThat(realm.isRootURLFromRequest(), is(false));
        assertThat(realm.isSendScopesInTokenRequest(), is(false));
        assertThat(realm.getProperties().get(Pkce.class), nullValue());
        assertThat(realm.getProperties().get(DisableTokenVerification.class), nullValue());
        assertThat(realm.getProperties().get(DisableNonce.class), nullValue());
        assertThat(realm.isTokenExpirationCheckDisabled(), is(false));
        assertThat(realm.isAllowTokenAccessWithoutOicSession(), is(false));
        var allowedTokenExpirationClockSkew = realm.getProperties().get(AllowedTokenExpirationClockSkew.class);
        assertThat(allowedTokenExpirationClockSkew, notNullValue());
        assertThat(allowedTokenExpirationClockSkew.getValueSeconds(), is(0));
    }

    private static Matcher<FormValidation> withMessageContaining(String message) {
        // the FormValidation message will be escaped for HTML, so we escape what we expect.
        return hasProperty("message", containsString(Util.escape(message)));
    }
}

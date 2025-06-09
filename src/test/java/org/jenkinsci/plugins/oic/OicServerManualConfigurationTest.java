package org.jenkinsci.plugins.oic;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.net.URISyntaxException;
import jenkins.security.FIPS140;
import org.hamcrest.Matcher;
import org.jenkinsci.plugins.oic.OicServerManualConfiguration.DescriptorImpl;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.mockito.MockedStatic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.jvnet.hudson.test.JenkinsMatchers.hasKind;
import static org.mockito.Mockito.mockStatic;

@WithJenkins
class OicServerManualConfigurationTest {

    @Test
    void ddoCheckTokenServerUrl(JenkinsRule jenkinsRule) {
        DescriptorImpl descriptor = getDescriptor(jenkinsRule);

        assertThat(
                descriptor.doCheckTokenServerUrl(null),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Token Server Url Key is required.")));
        assertThat(
                descriptor.doCheckTokenServerUrl(""),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Token Server Url Key is required.")));
        assertThat(descriptor.doCheckTokenServerUrl("http://localhost"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    void doCheckAuthorizationServerUrl(JenkinsRule jenkinsRule) {
        DescriptorImpl descriptor = getDescriptor(jenkinsRule);

        assertThat(
                descriptor.doCheckAuthorizationServerUrl(null),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Token Server Url Key is required.")));
        assertThat(
                descriptor.doCheckAuthorizationServerUrl(""),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessageContaining("Not a valid url.")));
        assertThat(descriptor.doCheckAuthorizationServerUrl("http://localhost"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    void doCheckJwksServerUrl(JenkinsRule jenkinsRule) {
        DescriptorImpl descriptor = getDescriptor(jenkinsRule);

        assertThat(descriptor.doCheckJwksServerUrl(null), hasKind(FormValidation.Kind.OK));
        assertThat(descriptor.doCheckJwksServerUrl(""), hasKind(FormValidation.Kind.OK));
        assertThat(descriptor.doCheckJwksServerUrl("http://localhost.jwks"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    void doCheckScopes(JenkinsRule jenkinsRule) {
        DescriptorImpl descriptor = getDescriptor(jenkinsRule);

        assertThat(
                descriptor.doCheckScopes(null),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Scopes is required.")));
        assertThat(
                descriptor.doCheckScopes(""),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Scopes is required.")));
        assertThat(
                descriptor.doCheckScopes("email username"),
                allOf(
                        hasKind(FormValidation.Kind.WARNING),
                        withMessage("Are you sure you don't want to include 'openid' as a scope?")));

        assertThat(descriptor.doCheckScopes("openid"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    void doCheckEndSessionEndpoint(JenkinsRule jenkinsRule) {
        DescriptorImpl descriptor = getDescriptor(jenkinsRule);

        assertThat(
                descriptor.doCheckEndSessionUrl(null),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("End Session URL Key is required.")));
        assertThat(
                descriptor.doCheckEndSessionUrl(""),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("End Session URL Key is required.")));
        assertThat(
                descriptor.doCheckEndSessionUrl("not a url"),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessageContaining("Not a valid url.")));
        assertThat(descriptor.doCheckEndSessionUrl("http://localhost.jwks"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    @WithoutJenkins
    public void testProviderMetadataWithFips() throws Descriptor.FormException {
        OicServerManualConfiguration config = new OicServerManualConfiguration("issuer", "t-url", "a-url");
        try (MockedStatic<FIPS140> fips140Mock = mockStatic(FIPS140.class)) {
            JWSAlgorithm.Family ed = JWSAlgorithm.Family.ED;
            JWSAlgorithm arbitraryEdAlgorithm = (JWSAlgorithm) ed.toArray()[0];

            fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(true);
            OIDCProviderMetadata data = config.toProviderMetadata();
            assertFalse(data.getIDTokenJWSAlgs().contains(arbitraryEdAlgorithm));

            fips140Mock.when(FIPS140::useCompliantAlgorithms).thenReturn(false);
            data = config.toProviderMetadata();
            assertTrue(data.getIDTokenJWSAlgs().contains(arbitraryEdAlgorithm));
        }
    }

    @Test
    @WithoutJenkins
    public void testProviderMetadataWithInvalidURI() throws Descriptor.FormException, URISyntaxException {
        OicServerManualConfiguration config = new OicServerManualConfiguration("issuer", "t-url", "inv%alid");
        assertThrows(IllegalStateException.class, () -> config.toProviderMetadata());
    }

    private static DescriptorImpl getDescriptor(JenkinsRule jenkinsRule) {
        return (DescriptorImpl) jenkinsRule.jenkins.getDescriptor(OicServerManualConfiguration.class);
    }

    private static Matcher<FormValidation> withMessage(String message) {
        // the FormValidation message will be escaped for HTML, so we escape what we expect.
        return hasProperty("message", is(Util.escape(message)));
    }

    private static Matcher<FormValidation> withMessageContaining(String message) {
        // the FormValidation message will be escaped for HTML, so we escape what we expect.
        return hasProperty("message", containsString(Util.escape(message)));
    }
}

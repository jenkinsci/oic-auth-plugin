package org.jenkinsci.plugins.oic;

import hudson.Util;
import hudson.util.FormValidation;
import java.io.IOException;
import org.hamcrest.Matcher;
import org.jenkinsci.plugins.oic.OicServerManualConfiguration.DescriptorImpl;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.jvnet.hudson.test.JenkinsMatchers.hasKind;

public class OicServerManualConfigurationTest {

    @ClassRule
    public static JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void ddoCheckTokenServerUrl() throws IOException {
        DescriptorImpl descriptor = getDescriptor();

        assertThat(
                descriptor.doCheckTokenServerUrl(null),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Token Server Url Key is required.")));
        assertThat(
                descriptor.doCheckTokenServerUrl(""),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Token Server Url Key is required.")));
        assertThat(descriptor.doCheckTokenServerUrl("http://localhost"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    public void doCheckAuthorizationServerUrl() throws IOException {
        DescriptorImpl descriptor = getDescriptor();

        assertThat(
                descriptor.doCheckAuthorizationServerUrl(null),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Token Server Url Key is required.")));
        assertThat(
                descriptor.doCheckAuthorizationServerUrl(""),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessageContaining("Not a valid url.")));
        assertThat(descriptor.doCheckAuthorizationServerUrl("http://localhost"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    public void doCheckJwksServerUrl() throws IOException {
        DescriptorImpl descriptor = getDescriptor();

        assertThat(descriptor.doCheckJwksServerUrl(null), hasKind(FormValidation.Kind.OK));
        assertThat(descriptor.doCheckJwksServerUrl(""), hasKind(FormValidation.Kind.OK));
        assertThat(descriptor.doCheckJwksServerUrl("http://localhost.jwks"), hasKind(FormValidation.Kind.OK));
    }

    @Test
    public void doCheckScopes() throws IOException {
        DescriptorImpl descriptor = getDescriptor();

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
    public void doCheckEndSessionEndpoint() throws IOException {
        DescriptorImpl descriptor = getDescriptor();

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

    private static DescriptorImpl getDescriptor() {
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

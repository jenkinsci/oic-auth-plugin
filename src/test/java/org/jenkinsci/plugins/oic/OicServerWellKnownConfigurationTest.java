package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.Util;
import hudson.util.FormValidation;
import java.io.IOException;
import org.hamcrest.Matcher;
import org.jenkinsci.plugins.oic.OicServerWellKnownConfiguration.DescriptorImpl;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.jvnet.hudson.test.JenkinsMatchers.hasKind;

public class OicServerWellKnownConfigurationTest {

    @ClassRule
    public static JenkinsRule jenkinsRule = new JenkinsRule();

    @Rule
    public WireMockRule wireMockRule =
            new WireMockRule(new WireMockConfiguration().dynamicPort().dynamicHttpsPort(), true);

    @Test
    public void doCheckWellKnownOpenIDConfigurationUrl() throws IOException {
        configureWireMockWellKnownEndpoint();
        DescriptorImpl descriptor = getDescriptor();

        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(null, false),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Not a valid url.")));
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl("", false),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Not a valid url.")));
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        "http://localhost:" + wireMockRule.port() + ("/.well-known/openid-configuration"), false),
                hasKind(FormValidation.Kind.OK));
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        wireMockRule.url("/.well-known/openid-configuration"), true), // disable TLS
                hasKind(FormValidation.Kind.OK));
        // TLS error.
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        wireMockRule.url("/.well-known/openid-configuration"), false),
                allOf(
                        hasKind(FormValidation.Kind.ERROR),
                        withMessageContaining("The server presented an invalid or incorrect TLS certificate")));

        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        jenkinsRule.jenkins.getRootUrl() + "/api/json", false),
                allOf(
                        hasKind(FormValidation.Kind.ERROR),
                        withMessageContaining("URL does not seem to describe OpenID Connect endpoints")));

        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(jenkinsRule.jenkins.getRootUrl() + "/api/xml", false),
                allOf(
                        hasKind(FormValidation.Kind.ERROR),
                        withMessageContaining("URL does not seem to describe OpenID Connect endpoints")));

        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        jenkinsRule.jenkins.getRootUrl() + "/does/not/exist", false),
                allOf(
                        hasKind(FormValidation.Kind.ERROR),
                        withMessageContaining("Error when retrieving well-known config")));
    }

    @Test
    public void doCheckOverrideScopes() throws IOException {
        DescriptorImpl descriptor = getDescriptor();

        assertThat(descriptor.doCheckOverrideScopes(null), hasKind(FormValidation.Kind.OK));
        assertThat(descriptor.doCheckOverrideScopes(""), hasKind(FormValidation.Kind.OK));
        assertThat(
                descriptor.doCheckOverrideScopes("openid email profile address phone offline_access"),
                hasKind(FormValidation.Kind.OK));
        assertThat(
                descriptor.doCheckOverrideScopes("blah"),
                allOf(
                        hasKind(FormValidation.Kind.WARNING),
                        withMessage("Are you sure you don't want to include 'openid' as a scope?")));
    }

    private void configureWireMockWellKnownEndpoint() {
        String authUrl = "http://localhost:" + wireMockRule.port() + "/authorization";
        String tokenUrl = "http://localhost:" + wireMockRule.port() + "/token";
        String userInfoUrl = "http://localhost:" + wireMockRule.port() + "/userinfo";
        String issuer = "http://localhost:" + wireMockRule.port() + "/";
        String jwksUrl = "null";
        String endSessionUrl = "null";

        wireMockRule.stubFor(get(urlPathEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withBody(String.format(
                                "{\"authorization_endpoint\": \"%s\", \"issuer\" :\"%s\", \"token_endpoint\":\"%s\", "
                                        + "\"userinfo_endpoint\":\"%s\",\"jwks_uri\":\"%s\", \"scopes_supported\": null, "
                                        + "\"subject_types_supported\": [ \"public\" ], "
                                        + "\"end_session_endpoint\":\"%s\"}",
                                authUrl, issuer, tokenUrl, userInfoUrl, jwksUrl, endSessionUrl))));
    }

    private static DescriptorImpl getDescriptor() {
        return (DescriptorImpl) jenkinsRule.jenkins.getDescriptor(OicServerWellKnownConfiguration.class);
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

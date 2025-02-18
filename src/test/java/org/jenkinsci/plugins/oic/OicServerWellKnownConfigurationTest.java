package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.Util;
import hudson.util.FormValidation;
import org.hamcrest.Matcher;
import org.jenkinsci.plugins.oic.OicServerWellKnownConfiguration.DescriptorImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.jvnet.hudson.test.JenkinsMatchers.hasKind;

@WithJenkins
class OicServerWellKnownConfigurationTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort().dynamicHttpsPort())
            .build();

    @Test
    void doCheckWellKnownOpenIDConfigurationUrl(JenkinsRule jenkinsRule) {
        configureWireMockWellKnownEndpoint(jenkinsRule);
        DescriptorImpl descriptor = getDescriptor(jenkinsRule);

        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(null, false),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Not a valid url.")));
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl("", false),
                allOf(hasKind(FormValidation.Kind.ERROR), withMessage("Not a valid url.")));
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        "http://localhost:" + wireMock.getPort() + ("/.well-known/openid-configuration"), false),
                hasKind(FormValidation.Kind.OK));
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        wireMock.url("/.well-known/openid-configuration"), true), // disable TLS
                hasKind(FormValidation.Kind.OK));
        // TLS error.
        assertThat(
                descriptor.doCheckWellKnownOpenIDConfigurationUrl(
                        wireMock.url("/.well-known/openid-configuration"), false),
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
    void doCheckOverrideScopes(JenkinsRule jenkinsRule) {
        DescriptorImpl descriptor = getDescriptor(jenkinsRule);

        assertThat(descriptor.doCheckScopesOverride(null), hasKind(FormValidation.Kind.OK));
        assertThat(descriptor.doCheckScopesOverride(""), hasKind(FormValidation.Kind.OK));
        assertThat(
                descriptor.doCheckScopesOverride("openid email profile address phone offline_access"),
                hasKind(FormValidation.Kind.OK));
        assertThat(
                descriptor.doCheckScopesOverride("blah"),
                allOf(
                        hasKind(FormValidation.Kind.WARNING),
                        withMessage("Are you sure you don't want to include 'openid' as a scope?")));
    }

    private void configureWireMockWellKnownEndpoint(JenkinsRule jenkinsRule) {
        String authUrl = "http://localhost:" + wireMock.getPort() + "/authorization";
        String tokenUrl = "http://localhost:" + wireMock.getPort() + "/token";
        String userInfoUrl = "http://localhost:" + wireMock.getPort() + "/userinfo";
        String issuer = "http://localhost:" + wireMock.getPort() + "/";
        String jwksUrl = "null";
        String endSessionUrl = "null";

        wireMock.stubFor(get(urlPathEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withBody(String.format(
                                "{\"authorization_endpoint\": \"%s\", \"issuer\" :\"%s\", \"token_endpoint\":\"%s\", "
                                        + "\"userinfo_endpoint\":\"%s\",\"jwks_uri\":\"%s\", \"scopes_supported\": null, "
                                        + "\"subject_types_supported\": [ \"public\" ], "
                                        + "\"end_session_endpoint\":\"%s\"}",
                                authUrl, issuer, tokenUrl, userInfoUrl, jwksUrl, endSessionUrl))));
    }

    private static DescriptorImpl getDescriptor(JenkinsRule jenkinsRule) {
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

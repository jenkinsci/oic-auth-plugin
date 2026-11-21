package org.jenkinsci.plugins.oic.properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.htmlunit.html.DomNode;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.jenkinsci.plugins.oic.OicSecurityRealm;
import org.jenkinsci.plugins.oic.OicServerManualConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class AllowedTokenExpirationClockSkewTest {

    private JenkinsRule jenkinsRule;
    private Jenkins jenkins;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        this.jenkinsRule = jenkinsRule;
        this.jenkins = jenkinsRule.getInstance();
    }

    @Test
    void newPropertyIsPrefilledWithDefaultValue() throws Exception {
        jenkins.setSecurityRealm(new OicSecurityRealm(
                "clientId",
                Secret.fromString("clientSecret"),
                new OicServerManualConfiguration(
                        "http://ignored.test/", "http://ignored.test/token", "http://ignored.test/authorize"),
                false,
                null,
                null));
        var descriptor = jenkins.getDescriptorByType(AllowedTokenExpirationClockSkew.DescriptorImpl.class);

        try (JenkinsRule.WebClient webClient = jenkinsRule.createWebClient()) {
            HtmlPage page = webClient.goTo("manage/configureSecurity");
            page.<HtmlButton>querySelector("button.hetero-list-add[suffix='properties']")
                    .click();
            for (DomNode item : page.querySelectorAll(".jenkins-dropdown__item")) {
                if (descriptor.getDisplayName().equals(item.getTextContent().trim())) {
                    ((HtmlButton) item).click();
                }
            }
            webClient.waitForBackgroundJavaScript(10_000);

            HtmlInput valueSeconds = page.querySelector("input[name='_.valueSeconds']");
            assertNotNull(valueSeconds, "the property should have been added to the form");
            assertEquals(String.valueOf(descriptor.getDefaultValueSeconds()), valueSeconds.getValue());

            jenkinsRule.submit(page.getFormByName("config"));
        }

        var property = ((OicSecurityRealm) jenkins.getSecurityRealm())
                .getProperties()
                .get(AllowedTokenExpirationClockSkew.class);
        assertNotNull(property);
        assertEquals(descriptor.getDefaultValueSeconds(), property.getValueSeconds());
    }
}

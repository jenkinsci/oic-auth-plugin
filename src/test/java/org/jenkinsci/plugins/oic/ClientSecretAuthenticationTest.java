package org.jenkinsci.plugins.oic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ClientSecretAuthenticationTest {

    private Jenkins jenkins;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        jenkins = jenkinsRule.getInstance();
    }

    @Test
    void getClientSecret_returnsNoneSentinelWhenNull() {
        assertEquals("none", Secret.toString(new ClientSecretAuthentication(null).getClientSecret()));
    }

    @Test
    void doCheckClientSecret() {
        ClientSecretAuthentication.DescriptorImpl descriptor = (ClientSecretAuthentication.DescriptorImpl)
                jenkins.getDescriptorOrDie(ClientSecretAuthentication.class);
        assertNotNull(descriptor);

        assertEquals(
                "Client secret is required.",
                descriptor.doCheckClientSecret(null).getMessage());
        assertEquals(
                "Client secret is required.", descriptor.doCheckClientSecret("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientSecret("password"));
    }
}

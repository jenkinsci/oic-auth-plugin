package org.jenkinsci.plugins.oic;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicSecurityRealm.DescriptorImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class DescriptorImplTest {

    private Jenkins jenkins;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        jenkins = jenkinsRule.getInstance();
    }

    @Test
    void testOicSecurityRealmDescriptorImplManual() throws Exception {
        OicSecurityRealm.DescriptorImpl descriptor = (DescriptorImpl) jenkins.getDescriptor(OicSecurityRealm.class);

        assertNotNull(descriptor);

        assertEquals("Login with Openid Connect", descriptor.getDisplayName());
        assertEquals("Client id is required.", descriptor.doCheckClientId(null).getMessage());
        assertEquals("Client id is required.", descriptor.doCheckClientId("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("goodClientId"));
        assertEquals(
                "Client secret is required.",
                descriptor.doCheckClientSecret(null).getMessage());
        assertEquals(
                "Client secret is required.", descriptor.doCheckClientSecret("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientSecret("password"));

        TestRealm realm = new TestRealm(new TestRealm.Builder("http://ignored.test/").WithAutomanualconfigure(false));
        jenkins.setSecurityRealm(realm);

        descriptor = (DescriptorImpl) realm.getDescriptor();
        assertNotNull(descriptor);

        assertThat(
                getConfiguredSecuritySecurityRealm().getServerConfiguration(),
                instanceOf(OicServerManualConfiguration.class));
    }

    @Test
    void testOicSecurityRealmDescriptorImplAuto() throws Exception {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals("Login with Openid Connect", descriptor.getDisplayName());
        assertEquals("Client id is required.", descriptor.doCheckClientId(null).getMessage());
        assertEquals("Client id is required.", descriptor.doCheckClientId("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("goodClientId"));
        assertEquals(
                "Client secret is required.",
                descriptor.doCheckClientSecret(null).getMessage());
        assertEquals(
                "Client secret is required.", descriptor.doCheckClientSecret("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckClientSecret("password"));

        TestRealm realm = new TestRealm(new TestRealm.Builder("http://ignored.test/").WithAutomanualconfigure(true));
        jenkins.setSecurityRealm(realm);

        descriptor = (DescriptorImpl) jenkins.getSecurityRealm().getDescriptor();

        assertNotNull(descriptor);

        assertThat(
                getConfiguredSecuritySecurityRealm().getServerConfiguration(),
                instanceOf(OicServerWellKnownConfiguration.class));
    }

    @Test
    void doCheckUserNameField() {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(
                FormValidation.ok("Using 'sub'.").getMessage(),
                descriptor.doCheckUserNameField(null).getMessage());
        assertEquals(
                FormValidation.ok("Using 'sub'.").getMessage(),
                descriptor.doCheckUserNameField("").getMessage());
        assertEquals(FormValidation.ok(), descriptor.doCheckUserNameField("subfield"));
    }

    @Test
    void doCheckFullNameFieldName() {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckFullNameFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckFullNameFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckFullNameFieldName("myname"));
    }

    @Test
    void doCheckEmailFieldName() {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckEmailFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckEmailFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckEmailFieldName("myemail"));
    }

    @Test
    void doCheckGroupsFieldName() {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckGroupsFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckGroupsFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckGroupsFieldName("mygroups"));
    }

    @Test
    void doCheckTokenFieldToCheckKey() {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckTokenFieldToCheckKey(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckTokenFieldToCheckKey("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckTokenFieldToCheckKey("akey"));
    }

    @Test
    void doCheckPostLogoutRedirectUrl() {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckPostLogoutRedirectUrl(null));
        assertEquals(FormValidation.ok(), descriptor.doCheckPostLogoutRedirectUrl(""));
        assertTrue(descriptor
                .doCheckPostLogoutRedirectUrl("not a url")
                .getMessage()
                .contains("Not a valid url."));
        assertEquals(FormValidation.ok(), descriptor.doCheckPostLogoutRedirectUrl("http://localhost"));
    }

    private OicSecurityRealm getConfiguredSecuritySecurityRealm() {
        return (OicSecurityRealm) jenkins.getSecurityRealm();
    }
}

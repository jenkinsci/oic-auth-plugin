package org.jenkinsci.plugins.oic;

import hudson.util.FormValidation;
import java.io.IOException;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicSecurityRealm.DescriptorImpl;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DescriptorImplTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    private Jenkins jenkins;

    @Before
    public void setUp() {
        jenkins = jenkinsRule.getInstance();
    }

    @Test
    public void testOicSecurityRealmDescriptorImplManual() throws Exception {
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
    public void testOicSecurityRealmDescriptorImplAuto() throws Exception {
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
    public void doCheckUserNameField() throws IOException {
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
    public void doCheckFullNameFieldName() throws IOException {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckFullNameFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckFullNameFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckFullNameFieldName("myname"));
    }

    @Test
    public void doCheckEmailFieldName() throws IOException {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckEmailFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckEmailFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckEmailFieldName("myemail"));
    }

    @Test
    public void doCheckGroupsFieldName() throws IOException {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckGroupsFieldName(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckGroupsFieldName("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckGroupsFieldName("mygroups"));
    }

    @Test
    public void doCheckTokenFieldToCheckKey() throws IOException {
        OicSecurityRealm.DescriptorImpl descriptor =
                (DescriptorImpl) jenkins.getDescriptorOrDie(OicSecurityRealm.class);

        assertEquals(FormValidation.ok(), descriptor.doCheckTokenFieldToCheckKey(""));
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckTokenFieldToCheckKey("]not valid").kind);
        assertEquals(FormValidation.ok(), descriptor.doCheckTokenFieldToCheckKey("akey"));
    }

    @Test
    public void doCheckPostLogoutRedirectUrl() throws IOException {
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

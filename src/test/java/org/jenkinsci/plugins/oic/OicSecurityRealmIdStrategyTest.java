package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.model.User;
import hudson.security.SecurityRealm;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsSessionRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class OicSecurityRealmIdStrategyTest {

    @Rule
    public JenkinsSessionRule sessions = new JenkinsSessionRule();

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(), true);

    @Test
    @Issue("SECURITY-3461")
    public void testUserIdStrategy_caseInsensitive() throws Throwable {
        sessions.then(r -> {
            TestRealm realm = new TestRealm(new TestRealm.Builder(wireMockRule)
                    .WithMinimalDefaults().WithUserIdStrategy(IdStrategy.CASE_INSENSITIVE));
            Jenkins.get().setSecurityRealm(realm);
            User testuser = User.getById("testuser", true);
            assertNotNull(testuser);
            assertEquals("testuser", testuser.getDisplayName());
            testuser.save();

            User testUSER = User.getById("testUSER", true);
            assertNotNull(testUSER);
            assertEquals("testuser", testUSER.getDisplayName());
            testUSER.save();

            assertEquals(testuser, testUSER);
        });
        sessions.then(r -> {
            User testuser = User.getById("testuser", false);
            assertNotNull(testuser);
            assertEquals("testuser", testuser.getDisplayName());

            User testUSER = User.getById("testUSER", false);
            assertNotNull(testUSER);
            assertEquals("testuser", testUSER.getDisplayName());
            assertEquals(testuser, testUSER);
        });
    }

    @Test
    @Issue("SECURITY-3461")
    public void testUserIdStrategy_caseSensitive() throws Throwable {
        sessions.then(r -> {
            TestRealm realm = new TestRealm(new TestRealm.Builder(wireMockRule)
                    .WithMinimalDefaults().WithUserIdStrategy(new IdStrategy.CaseSensitive()));
            Jenkins.get().setSecurityRealm(realm);
            User testuser = User.getById("testuser", true);
            assertNotNull(testuser);
            assertEquals("testuser", testuser.getDisplayName());
            testuser.save();

            User testUSER = User.getById("testUSER", true);
            assertNotNull(testUSER);
            assertEquals("testUSER", testUSER.getDisplayName());
            testUSER.save();

            assertNotEquals(testuser, testUSER);
        });
        sessions.then(r -> {
            User testuser = User.getById("testuser", false);
            assertNotNull(testuser);
            assertEquals("testuser", testuser.getDisplayName());

            User testUSER = User.getById("testUSER", false);
            assertNotNull(testUSER);
            assertEquals("testUSER", testUSER.getDisplayName());

            assertNotEquals(testuser, testUSER);
        });
    }

    @Test
    @Issue("SECURITY-3461")
    public void testUserIdStrategy_default() throws Throwable {
        sessions.then(r -> {
            TestRealm realm = new TestRealm(wireMockRule);
            Jenkins.get().setSecurityRealm(realm);
        });
        sessions.then(r -> {
            // when restarting, ensure the default case-insensitive is used
            SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
            assertThat(securityRealm, instanceOf(OicSecurityRealm.class));
            OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) securityRealm;
            assertTrue(oicSecurityRealm.isMissingIdStrategy());
            assertEquals(IdStrategy.CASE_INSENSITIVE, securityRealm.getUserIdStrategy());
            assertEquals(IdStrategy.CASE_INSENSITIVE, securityRealm.getGroupIdStrategy());

            TestRealm realm = new TestRealm(new TestRealm.Builder(wireMockRule)
                    .WithMinimalDefaults()
                            .WithUserIdStrategy(IdStrategy.CASE_INSENSITIVE)
                            .WithGroupIdStrategy(IdStrategy.CASE_INSENSITIVE));
            Jenkins.get().setSecurityRealm(realm);
            assertFalse(realm.isMissingIdStrategy());
        });
    }
}

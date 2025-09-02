package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.User;
import hudson.security.SecurityRealm;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class OicSecurityRealmIdStrategyTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort())
            .build();

    @Test
    @Issue("SECURITY-3461")
    void testUserIdStrategy_caseInsensitive(JenkinsRule r) throws Throwable {
        TestRealm realm = new TestRealm(
                new TestRealm.Builder(wireMock).WithMinimalDefaults().WithUserIdStrategy(IdStrategy.CASE_INSENSITIVE));
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

        r.restart();

        testuser = User.getById("testuser", false);
        assertNotNull(testuser);
        assertEquals("testuser", testuser.getDisplayName());

        testUSER = User.getById("testUSER", false);
        assertNotNull(testUSER);
        assertEquals("testuser", testUSER.getDisplayName());
        assertEquals(testuser, testUSER);
    }

    @Test
    @Issue("SECURITY-3461")
    void testUserIdStrategy_caseSensitive(JenkinsRule r) throws Throwable {
        TestRealm realm = new TestRealm(new TestRealm.Builder(wireMock)
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

        r.restart();

        testuser = User.getById("testuser", false);
        assertNotNull(testuser);
        assertEquals("testuser", testuser.getDisplayName());

        testUSER = User.getById("testUSER", false);
        assertNotNull(testUSER);
        assertEquals("testUSER", testUSER.getDisplayName());

        assertNotEquals(testuser, testUSER);
    }

    @Test
    @Issue("SECURITY-3461")
    void testUserIdStrategy_default(JenkinsRule r) throws Throwable {
        TestRealm realm = new TestRealm(wireMock);
        Jenkins.get().setSecurityRealm(realm);

        r.restart();

        // when restarting, ensure the default case-insensitive is used
        SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
        assertThat(securityRealm, instanceOf(OicSecurityRealm.class));
        OicSecurityRealm oicSecurityRealm = (OicSecurityRealm) securityRealm;
        assertTrue(oicSecurityRealm.isMissingIdStrategy());
        assertEquals(IdStrategy.CASE_INSENSITIVE, securityRealm.getUserIdStrategy());
        assertEquals(IdStrategy.CASE_INSENSITIVE, securityRealm.getGroupIdStrategy());

        realm = new TestRealm(new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithUserIdStrategy(IdStrategy.CASE_INSENSITIVE)
                        .WithGroupIdStrategy(IdStrategy.CASE_INSENSITIVE));
        Jenkins.get().setSecurityRealm(realm);
        assertFalse(realm.isMissingIdStrategy());
    }
}

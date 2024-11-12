package org.jenkinsci.plugins.oic.monitor;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.TestRealm;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsSessionRule;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OicStrategyMonitorTest {

    @Rule
    public JenkinsSessionRule sessions = new JenkinsSessionRule();

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(), true);

    @Test
    @Issue("SECURITY-3461")
    public void smokes_caseInsensitive() throws Throwable {
        sessions.then(r -> {
            TestRealm realm = new TestRealm(wireMockRule);
            Jenkins.get().setSecurityRealm(realm);
            assertTrue(OicIdStrategyMonitor.get().isActivated());
        });
        sessions.then(r -> {
            assertTrue(OicIdStrategyMonitor.get().isActivated());
            TestRealm realm = new TestRealm(new TestRealm.Builder(wireMockRule)
                    .WithMinimalDefaults()
                            .WithGroupIdStrategy(IdStrategy.CASE_INSENSITIVE)
                            .WithUserIdStrategy(IdStrategy.CASE_INSENSITIVE));
            Jenkins.get().setSecurityRealm(realm);
            assertFalse(OicIdStrategyMonitor.get().isActivated());
        });
        sessions.then(r -> {
            assertFalse(OicIdStrategyMonitor.get().isActivated());
        });
    }

    @Test
    @Issue("SECURITY-3461")
    public void smokes_noChange() throws Throwable {
        sessions.then(r -> {
            TestRealm realm = new TestRealm(wireMockRule);
            Jenkins.get().setSecurityRealm(realm);
            assertTrue(OicIdStrategyMonitor.get().isActivated());
        });
        sessions.then(r -> {
            assertTrue(OicIdStrategyMonitor.get().isActivated());
        });
    }
}

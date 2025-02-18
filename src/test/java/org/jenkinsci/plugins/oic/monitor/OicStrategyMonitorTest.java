package org.jenkinsci.plugins.oic.monitor;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import jenkins.model.IdStrategy;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.TestRealm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class OicStrategyMonitorTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort())
            .build();

    @Test
    @Issue("SECURITY-3461")
    void smokes_caseInsensitive(JenkinsRule r) throws Throwable {
        TestRealm realm = new TestRealm(wireMock);
        Jenkins.get().setSecurityRealm(realm);
        assertTrue(OicIdStrategyMonitor.get().isActivated());

        r.restart();

        assertTrue(OicIdStrategyMonitor.get().isActivated());
        realm = new TestRealm(new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithGroupIdStrategy(IdStrategy.CASE_INSENSITIVE)
                        .WithUserIdStrategy(IdStrategy.CASE_INSENSITIVE));
        Jenkins.get().setSecurityRealm(realm);
        assertFalse(OicIdStrategyMonitor.get().isActivated());

        r.restart();

        assertFalse(OicIdStrategyMonitor.get().isActivated());
    }

    @Test
    @Issue("SECURITY-3461")
    void smokes_noChange(JenkinsRule r) throws Throwable {
        TestRealm realm = new TestRealm(wireMock);
        Jenkins.get().setSecurityRealm(realm);
        assertTrue(OicIdStrategyMonitor.get().isActivated());

        r.restart();

        assertTrue(OicIdStrategyMonitor.get().isActivated());
    }
}

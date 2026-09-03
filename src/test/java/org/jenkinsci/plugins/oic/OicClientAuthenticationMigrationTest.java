package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

import hudson.init.InitMilestone;
import hudson.util.Secret;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

/**
 * Verifies that a {@link OicSecurityRealm} previously persisted with the legacy flat
 * {@code clientSecret} field (before it was split into the {@link ClientSecretAuthentication} /
 * {@link JwtBearerClientAuthentication} describables) is migrated on load to a
 * {@link ClientSecretAuthentication}.
 */
@WithJenkins
class OicClientAuthenticationMigrationTest {

    @Test
    @LocalData
    void migratesLegacyClientSecretTest(JenkinsRule j) {
        assertThat("Instance is up and running with no errors", j.jenkins.getInitLevel(), is(InitMilestone.COMPLETED));
        OicSecurityRealm realm = (OicSecurityRealm) j.jenkins.getSecurityRealm();
        assertThat(realm.getClientId(), is("client-id"));
        assertThat(realm.getClientAuthentication(), instanceOf(ClientSecretAuthentication.class));
        var clientAuthentication = (ClientSecretAuthentication) realm.getClientAuthentication();
        assertThat(Secret.toString(clientAuthentication.getClientSecret()), is("legacy-plain-secret"));
    }
}

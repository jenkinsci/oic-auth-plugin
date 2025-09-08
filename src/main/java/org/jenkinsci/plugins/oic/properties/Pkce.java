package org.jenkinsci.plugins.oic.properties;

import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.plugins.oic.OicPropertyExecution;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.jenkinsci.plugins.oic.OidcProperty;
import org.jenkinsci.plugins.oic.OidcPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Enables and configures PKCE (Proof Key for Code Exchange) for OIDC authentication.
 * PKCE is a security measure to prevent authorization code interception attacks.
 */
public class Pkce extends OidcProperty {
    @DataBoundConstructor
    public Pkce() {}

    @NonNull
    @Override
    public OicPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl(serverConfiguration);
    }

    private record ExecutionImpl(OicServerConfiguration serverConfiguration) implements OicPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull OidcConfiguration configuration) {
            configuration.setDisablePkce(false);
            configuration.setPkceMethod(CodeChallengeMethod.S256);
        }
    }

    @Extension
    public static class DescriptorImpl extends OidcPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.PKCE_DisplayName();
        }

        @Override
        public void getFallbackConfiguration(
                @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
            configuration.setDisablePkce(true);
        }
    }
}

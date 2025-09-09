package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.jenkinsci.plugins.oic.OidcProperty;
import org.jenkinsci.plugins.oic.OidcPropertyDescriptor;
import org.jenkinsci.plugins.oic.OidcPropertyExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Disables the use of nonce in OIDC authentication.
 * This is generally not recommended as it can lead to replay attacks.
 */
public class DisableNonce extends OidcProperty {
    @DataBoundConstructor
    public DisableNonce() {}

    @NonNull
    @Override
    public OidcPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl();
    }

    private record ExecutionImpl() implements OidcPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull OidcConfiguration configuration) {
            configuration.setUseNonce(false);
        }
    }

    @Extension
    public static class DescriptorImpl extends OidcPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.DisableNonce_DisplayName();
        }

        @Override
        public void getFallbackConfiguration(
                @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
            configuration.setUseNonce(true);
        }
    }
}

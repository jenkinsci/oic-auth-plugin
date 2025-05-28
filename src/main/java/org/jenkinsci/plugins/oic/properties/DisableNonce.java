package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.plugins.oic.OicProperty;
import org.jenkinsci.plugins.oic.OicPropertyDescriptor;
import org.jenkinsci.plugins.oic.OicPropertyExecution;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.config.OidcConfiguration;

public class DisableNonce extends OicProperty {
    @DataBoundConstructor
    public DisableNonce() {}

    @NonNull
    @Override
    public OicPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl();
    }

    private record ExecutionImpl() implements OicPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull OidcConfiguration configuration) {
            configuration.setUseNonce(false);
        }
    }

    @Extension
    public static class DescriptorImpl extends OicPropertyDescriptor {
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

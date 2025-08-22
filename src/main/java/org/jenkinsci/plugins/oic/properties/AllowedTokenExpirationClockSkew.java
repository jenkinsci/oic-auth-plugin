package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.plugins.oic.OicProperty;
import org.jenkinsci.plugins.oic.OicPropertyDescriptor;
import org.jenkinsci.plugins.oic.OicPropertyExecution;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Configures the allowed clock skew for token expiration.
 * This is useful to accommodate for clock differences between the server and the OIDC provider.
 */
public class AllowedTokenExpirationClockSkew extends OicProperty {
    private int value;

    @DataBoundConstructor
    public AllowedTokenExpirationClockSkew(int value) {
        this.value = value;
    }

    @NonNull
    @Override
    public OicPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl(value);
    }

    private record ExecutionImpl(int value) implements OicPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull OidcConfiguration configuration) {
            configuration.setMaxClockSkew(value);
        }
    }

    @Extension
    public static class DescriptorImpl extends OicPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.AllowedTokenExpirationClockSkew_DisplayName();
        }

        @Override
        public void getFallbackConfiguration(
                @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
            configuration.setMaxClockSkew(getDefaultValue());
        }

        public int getDefaultValue() {
            return 60; // Default value for clock skew in seconds
        }
    }
}

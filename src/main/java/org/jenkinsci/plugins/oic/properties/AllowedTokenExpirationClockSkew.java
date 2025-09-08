package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.plugins.oic.OidcProperty;
import org.jenkinsci.plugins.oic.OidcPropertyDescriptor;
import org.jenkinsci.plugins.oic.OicPropertyExecution;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Configures the allowed clock skew for token expiration.
 * This is useful to accommodate for clock differences between the server and the OIDC provider.
 */
public class AllowedTokenExpirationClockSkew extends OidcProperty {
    private int valueSeconds;

    @DataBoundConstructor
    public AllowedTokenExpirationClockSkew(int valueSeconds) {
        this.valueSeconds = valueSeconds;
    }

    public int getValueSeconds() {
        return valueSeconds;
    }

    @NonNull
    @Override
    public OicPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl(valueSeconds);
    }

    private record ExecutionImpl(int valueSeconds) implements OicPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull OidcConfiguration configuration) {
            configuration.setMaxClockSkew(valueSeconds);
        }
    }

    @Extension
    public static class DescriptorImpl extends OidcPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.AllowedTokenExpirationClockSkew_DisplayName();
        }

        @Override
        public void getFallbackConfiguration(
                @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
            configuration.setMaxClockSkew(getDefaultValueSeconds());
        }

        public int getDefaultValueSeconds() {
            return 60; // Default value for clock skew in seconds
        }
    }
}

package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import jenkins.security.FIPS140;
import org.apache.commons.lang.Validate;
import org.jenkinsci.plugins.oic.AnythingGoesTokenValidator;
import org.jenkinsci.plugins.oic.OidcProperty;
import org.jenkinsci.plugins.oic.OidcPropertyDescriptor;
import org.jenkinsci.plugins.oic.OicPropertyExecution;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver;
import org.pac4j.oidc.profile.creator.TokenValidator;

/**
 * Disable token verification.
 */
public class DisableTokenVerification extends OidcProperty {
    @DataBoundConstructor
    public DisableTokenVerification() {
        Validate.isTrue(!FIPS140.useCompliantAlgorithms(), "Token verification can not be disabled");
    }

    @NonNull
    @Override
    public OicPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl(serverConfiguration);
    }

    private record ExecutionImpl(OicServerConfiguration serverConfiguration) implements OicPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull OidcConfiguration configuration) {
            configuration.setAllowUnsignedIdTokens(true);

            var opMetadataResolver =
                    new StaticOidcOpMetadataResolver(configuration, serverConfiguration.toProviderMetadata()) {
                        @Override
                        protected TokenValidator createTokenValidator() {
                            return new AnythingGoesTokenValidator();
                        }
                    };
            configuration.setOpMetadataResolver(opMetadataResolver);
            opMetadataResolver.init();
        }

        @Override
        public void customizeClient(@NonNull OidcClient client) {
            OicPropertyExecution.super.customizeClient(client);
        }
    }

    @Extension
    public static class DescriptorImpl extends OidcPropertyDescriptor {
        @Override
        public boolean isApplicable() {
            return !FIPS140.useCompliantAlgorithms();
        }

        @Override
        public void getFallbackConfiguration(
                @NonNull OicServerConfiguration serverConfiguration, @NonNull OidcConfiguration configuration) {
            var opMetadataResolver =
                    new StaticOidcOpMetadataResolver(configuration, serverConfiguration.toProviderMetadata());
            configuration.setOpMetadataResolver(opMetadataResolver);
            opMetadataResolver.init();
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.DisableTokenVerification_DisplayName();
        }
    }
}

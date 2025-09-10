package org.jenkinsci.plugins.oic.properties;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import java.io.Serial;
import jenkins.security.FIPS140;
import org.apache.commons.lang.Validate;
import org.jenkinsci.plugins.oic.AnythingGoesTokenValidator;
import org.jenkinsci.plugins.oic.OicServerConfiguration;
import org.jenkinsci.plugins.oic.OidcProperty;
import org.jenkinsci.plugins.oic.OidcPropertyDescriptor;
import org.jenkinsci.plugins.oic.OidcPropertyExecution;
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
    public OidcPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new ExecutionImpl(serverConfiguration);
    }

    @Serial
    protected Object readResolve() {
        if (FIPS140.useCompliantAlgorithms()) {
            throw new IllegalStateException(org.jenkinsci.plugins.oic.Messages.OicSecurityRealm_DisableTokenVerificationFipsMode());
        }
        return this;
    }

    private record ExecutionImpl(OicServerConfiguration serverConfiguration) implements OidcPropertyExecution {
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
            OidcPropertyExecution.super.customizeClient(client);
        }
    }

    public static class DescriptorImpl extends OidcPropertyDescriptor {
        @Extension
        @CheckForNull
        public static DescriptorImpl createIfApplicable() {
            if (FIPS140.useCompliantAlgorithms()) {
                return null;
            }
            return new DescriptorImpl();
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

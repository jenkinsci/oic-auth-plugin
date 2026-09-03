package org.jenkinsci.plugins.oic;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.clientauth.ClientAuthenticationBuilder;
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver;
import org.pac4j.oidc.profile.creator.TokenValidator;

/**
 * Authenticates to the token endpoint using a JWT bearer client assertion (RFC 7523) read from a
 * file, e.g. a Kubernetes service account token mounted via workload identity federation.
 *
 * <p>The file is re-read on every token request, so that token rotation (as performed by
 * Kubernetes) is supported without restarting Jenkins.
 */
public class JwtBearerClientAuthentication extends OicClientAuthentication {

    private static final long serialVersionUID = 1L;

    private final String clientAssertionFilePath;

    @DataBoundConstructor
    public JwtBearerClientAuthentication(String clientAssertionFilePath) {
        this.clientAssertionFilePath = Util.fixEmptyAndTrim(clientAssertionFilePath);
    }

    @CheckForNull
    public String getClientAssertionFilePath() {
        return clientAssertionFilePath;
    }

    @Override
    protected void configure(@NonNull OidcConfiguration oidcConfiguration) {
        // set method to PRIVATE_KEY_JWT so pac4j does not require a client secret.
        // The actual assertion is applied via the custom resolver in customizeOidcConfiguration().
        oidcConfiguration.setClientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    }

    @Override
    protected void customizeOidcConfiguration(
            @NonNull OidcConfiguration oidcConfiguration,
            @NonNull OicServerConfiguration serverConfiguration,
            @NonNull String clientId) {
        Path filePath = Path.of(clientAssertionFilePath);

        var existingResolver = oidcConfiguration.getOpMetadataResolver();
        OIDCProviderMetadata metadata =
                (existingResolver != null) ? existingResolver.load() : serverConfiguration.toProviderMetadata();
        TokenValidator existingTokenValidator =
                (existingResolver != null) ? existingResolver.getTokenValidator() : null;

        var jwtBearerResolver = new StaticOidcOpMetadataResolver(oidcConfiguration, metadata) {
            @Override
            protected void internalLoad() {
                super.internalLoad();
                var jwtAuth = new FileJwtClientAuthentication(clientId, filePath);
                ClientAuthenticationBuilder jwtBuilder = new ClientAuthenticationBuilder() {
                    @Override
                    public void buildClientAuthentication() {}

                    @Override
                    public ClientAuthentication getClientAuthentication() {
                        return jwtAuth;
                    }
                };
                clientAuthToken = jwtBuilder;
                clientAuthPar = jwtBuilder;
            }

            @Override
            protected TokenValidator createTokenValidator() {
                return existingTokenValidator != null ? existingTokenValidator : super.createTokenValidator();
            }
        };
        oidcConfiguration.setOpMetadataResolver(jwtBearerResolver);
        jwtBearerResolver.init();
    }

    @Extension
    @Symbol("jwtBearer")
    public static class DescriptorImpl extends Descriptor<OicClientAuthentication> {

        @Override
        public String getDisplayName() {
            return Messages.JwtBearerClientAuthentication_DisplayName();
        }

        @RequirePOST
        public FormValidation doCheckClientAssertionFilePath(@QueryParameter String clientAssertionFilePath) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            String trimmed = Util.fixEmptyAndTrim(clientAssertionFilePath);
            if (trimmed == null) {
                return FormValidation.error(Messages.OicSecurityRealm_ClientAssertionFilePathRequired());
            }
            try {
                Path path = Path.of(trimmed);
                if (!path.isAbsolute()) {
                    return FormValidation.error(Messages.OicSecurityRealm_ClientAssertionFilePathMustBeAbsolute());
                }
                if (!path.toFile().exists()) {
                    return FormValidation.warning(Messages.OicSecurityRealm_ClientAssertionFilePathDoesNotExist());
                }
            } catch (InvalidPathException e) {
                return FormValidation.error(Messages.OicSecurityRealm_ClientAssertionFilePathInvalid());
            }
            return FormValidation.ok();
        }
    }
}

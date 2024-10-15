package org.jenkinsci.plugins.oic;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver;
import org.pac4j.oidc.profile.creator.TokenValidator;

public class OicdPluginOpMetadataResolver extends StaticOidcOpMetadataResolver {

    private boolean allowsAnything;

    public OicdPluginOpMetadataResolver(
            OidcConfiguration configuration, OIDCProviderMetadata staticMetadata, boolean allowsAnything) {
        super(configuration, staticMetadata);
        this.allowsAnything = allowsAnything;
    }

    @Override
    protected TokenValidator createTokenValidator() {
        if (allowsAnything) {
            return new AnythingGoesTokenValidator();
        }

        return super.createTokenValidator();
    }

    /**
     * This method is needed as there seems to be a bug in pac4j and hasChanged is not able to return true
     * This will make it work until the bug is fixed.
     * TODO eventually remove
     */
    @Override
    public boolean hasChanged() {
        return true;
    }
}

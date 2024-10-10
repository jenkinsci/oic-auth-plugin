package org.jenkinsci.plugins.oic;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver;
import org.pac4j.oidc.profile.creator.TokenValidator;

public class AnythingGoesOpMetadataResolver extends StaticOidcOpMetadataResolver {

    public AnythingGoesOpMetadataResolver(OidcConfiguration configuration, OIDCProviderMetadata staticMetadata) {
        super(configuration, staticMetadata);
    }

    @Override
    protected TokenValidator createTokenValidator() {
        return new AnythingGoesTokenValidator();
    }
}

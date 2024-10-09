package org.jenkinsci.plugins.oic;

import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.metadata.OidcOpMetadataResolver;
import org.pac4j.oidc.profile.creator.TokenValidator;

public class AnythingGoesOpMetadataResolver extends OidcOpMetadataResolver {

    public AnythingGoesOpMetadataResolver(OidcConfiguration configuration) {
        super(configuration);
    }

    @Override
    protected TokenValidator createTokenValidator() {
        return new AnythingGoesTokenValidator();
    }
}

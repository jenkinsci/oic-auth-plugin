package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.Describable;
import java.io.Serial;
import java.io.Serializable;
import org.pac4j.oidc.config.OidcConfiguration;

/**
 * Extension point defining how the {@link OicSecurityRealm} authenticates itself to the OpenID
 * Connect provider's token endpoint, e.g. using a client secret or a JWT bearer assertion.
 */
public abstract class OicClientAuthentication
        implements Describable<OicClientAuthentication>, ExtensionPoint, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Configure the client secret / authentication method needed to authenticate to the token
     * endpoint on the given {@link OidcConfiguration}.
     */
    protected abstract void configure(@NonNull OidcConfiguration oidcConfiguration);

    /**
     * Allows further customization of the fully built {@link OidcConfiguration}, once all
     * {@link OidcProperty} customizations have been applied. Most implementations do not need to
     * override this; the default is a no-op.
     *
     * @param clientId the OAuth2 client id configured on the {@link OicSecurityRealm}
     */
    protected void customizeOidcConfiguration(
            @NonNull OidcConfiguration oidcConfiguration,
            @NonNull OicServerConfiguration serverConfiguration,
            @NonNull String clientId) {
        // no-op by default
    }
}

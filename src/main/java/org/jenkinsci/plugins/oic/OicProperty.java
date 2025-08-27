package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.AbstractDescribableImpl;
import java.util.List;
import java.util.Optional;
import org.springframework.security.core.Authentication;

/**
 * Represents a property that can be configured for OIDC authentication.
 */
public abstract class OicProperty extends AbstractDescribableImpl<OicProperty> {
    /**
     * @return a new execution for this property, holding any required state.
     */
    @NonNull
    public OicPropertyExecution newExecution(@NonNull OicServerConfiguration serverConfiguration) {
        return new EmptyExecution();
    }

    private record EmptyExecution() implements OicPropertyExecution {}

    /**
     * Allows a property to authenticate the user.
     * @see org.jenkinsci.plugins.oic.properties.EscapeHatch
     */
    public Optional<Authentication> authenticate(Authentication authentication) {
        return Optional.empty();
    }

    /**
     * Allows a property to contribute additional query parameters to the logout request.
     */
    @NonNull
    public List<LogoutQueryParameter> contributeLogoutQueryParameters() {
        return List.of();
    }
}

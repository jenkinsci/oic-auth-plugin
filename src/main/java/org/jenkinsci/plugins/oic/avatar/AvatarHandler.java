package org.jenkinsci.plugins.oic.avatar;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import hudson.model.User;
import java.io.IOException;
import java.io.Serializable;
import org.jenkinsci.plugins.oic.OicSecurityRealm;

/**
 * Strategy for how a user's avatar, as advertised by the OpenID Connect provider, is made available
 * to Jenkins pages.
 * Selected by the administrator in the security realm configuration.
 */
public abstract class AvatarHandler extends AbstractDescribableImpl<AvatarHandler>
        implements ExtensionPoint, Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Record, refresh or clear the avatar for {@code user}.
     * <p>
     * Called on the login request thread, so implementations must return promptly: anything needing
     * network IO must be handled asynchronously.
     *
     * @param avatarUrl the value of the provider's avatar claim, or {@code null} if it was not present.
     */
    public abstract void handleAvatar(
            @NonNull OicSecurityRealm realm, @NonNull User user, @CheckForNull String avatarUrl) throws IOException;
}

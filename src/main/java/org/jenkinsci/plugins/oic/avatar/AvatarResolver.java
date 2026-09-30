package org.jenkinsci.plugins.oic.avatar;

import hudson.Extension;
import hudson.model.User;
import hudson.tasks.UserAvatarResolver;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.OicSecurityRealm;

/**
 * Exposes the avatar recorded by the configured {@link AvatarHandler} to the rest of Jenkins.
 */
@Extension
public class AvatarResolver extends UserAvatarResolver {

    /**
     * {@inheritDoc}
     * <p>
     * {@code width} and {@code height} are ignored: so the image is always served at its natural size
     * and scaling will occur on the browser.
     */
    @Override
    public String findAvatarFor(User user, int width, int height) {
        // stop serving OIDC avatars if the administrator has switched away from this realm
        if (user == null || !(Jenkins.get().getSecurityRealm() instanceof OicSecurityRealm)) {
            return null;
        }
        AvatarProperty avatarProperty = user.getProperty(AvatarProperty.class);
        return avatarProperty == null ? null : avatarProperty.getAvatarUrl();
    }
}

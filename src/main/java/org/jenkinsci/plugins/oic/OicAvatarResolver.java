package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.model.User;
import hudson.tasks.UserAvatarResolver;

@Extension
public class OicAvatarResolver extends UserAvatarResolver {
    @Override
    public String findAvatarFor(User user, int width, int height) {
        if (user != null) {
            OicAvatarProperty avatarProperty = user.getProperty(OicAvatarProperty.class);
            if (avatarProperty != null) {
                return avatarProperty.getAvatarUrl();
            }
        }
        return null;
    }
}

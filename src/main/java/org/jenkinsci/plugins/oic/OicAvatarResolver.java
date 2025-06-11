package org.jenkinsci.plugins.oic;

import com.google.common.annotations.VisibleForTesting;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.User;
import hudson.tasks.UserAvatarResolver;

@Extension
public class OicAvatarResolver extends UserAvatarResolver {

    @VisibleForTesting
    protected static ExtensionList<OicAvatarResolver> get() {
        return ExtensionList.lookup(OicAvatarResolver.class);
    }

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

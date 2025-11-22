package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import jenkins.security.csp.AvatarContributor;

public class OicAvatarProperty extends UserProperty {

    private final AvatarImage avatarImage;

    public OicAvatarProperty(AvatarImage avatarImage) {
        this.avatarImage = avatarImage;
        if (avatarImage != null) {
            AvatarContributor.allow(avatarImage.url);
        }
    }

    public String getAvatarUrl() {
        if (isHasAvatar()) {
            return getAvatarImageUrl();
        }
        return null;
    }

    private String getAvatarImageUrl() {
        return avatarImage.url;
    }

    public boolean isHasAvatar() {
        return avatarImage != null && avatarImage.isValid();
    }

    public String getDisplayName() {
        return "OpenID Connect Avatar";
    }

    public String getIconFileName() {
        return null;
    }

    public String getUrlName() {
        return "oic-avatar";
    }

    private Object readResolve() {
        if (avatarImage != null) {
            AvatarContributor.allow(avatarImage.url);
        }
        return this;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        @NonNull
        public String getDisplayName() {
            return "OpenID Connect Avatar";
        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public UserProperty newInstance(User user) {
            return new OicAvatarProperty(null);
        }
    }

    /**
     * OIC avatar is standard picture field on the profile claim.
     */
    public static class AvatarImage {
        private final String url;

        public AvatarImage(String url) {
            this.url = url;
        }

        public boolean isValid() {
            return url != null;
        }
    }
}

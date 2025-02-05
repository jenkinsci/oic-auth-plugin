package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import java.io.File;
import java.io.FileInputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;

public class OicAvatarProperty extends UserProperty implements Action {
    private static final Logger LOGGER = Logger.getLogger(OicAvatarProperty.class.getName());

    private final AvatarImage avatarImage;

    public OicAvatarProperty(AvatarImage avatarImage) {
        this.avatarImage = avatarImage;
    }

    public String getAvatarUrl() {
        if (isHasAvatar()) {
            return getAvatarImageUrl();
        }
        return null;
    }

    private String getAvatarImageUrl() {
        return "%s%s/%s/image".formatted(Jenkins.get().getRootUrl(), user.getUrl(), getUrlName());
    }

    public boolean isHasAvatar() {
        return avatarImage != null && avatarImage.isValid();
    }

    /**
     * Used to serve images as part of {@link OicAvatarResolver}.
     */
    public void doImage(StaplerRequest2 req, StaplerResponse2 rsp) {
        if (avatarImage == null) {
            LOGGER.log(Level.WARNING, "No image set for user '" + user.getId() + "'");
            return;
        }

        String imageFileName = "oic-avatar." + avatarImage.getFilenameSuffix();
        File file = new File(user.getUserFolder(), imageFileName);
        if (!file.exists()) {
            LOGGER.log(Level.WARNING, "Avatar image for user '" + user.getId() + "' does not exist");
            return;
        }

        try (FileInputStream fileInputStream = new FileInputStream(file); ) {
            rsp.setContentType(avatarImage.mimeType);
            rsp.serveFile(req, fileInputStream, file.lastModified(), file.length(), imageFileName);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Unable to write image for user '" + user.getId() + "'", e);
        }
    }

    public String getDisplayName() {
        return "Openid Connect Avatar";
    }

    public String getIconFileName() {
        return null;
    }

    public String getUrlName() {
        return "oic-avatar";
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        @NonNull
        public String getDisplayName() {
            return "Openid Connect Avatar";
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

    public static class AvatarImage {
        private final String mimeType;

        public AvatarImage(String mimeType) {
            this.mimeType = mimeType;
        }

        public String getFilenameSuffix() {
            return mimeType.split("/")[1].split("\\+")[0];
        }

        public boolean isValid() {
            return mimeType != null;
        }
    }
}

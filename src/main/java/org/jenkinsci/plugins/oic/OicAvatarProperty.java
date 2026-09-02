package org.jenkinsci.plugins.oic;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import jakarta.servlet.ServletException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Set;
import jenkins.security.csp.AvatarContributor;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerResponse2;

public class OicAvatarProperty extends UserProperty implements Action {

    static final String AVATAR_FILE_NAME = "oic-avatar";

    /** Set when the avatar is referenced on the identity provider instead of being stored by Jenkins. */
    private final AvatarImage avatarImage;
    /** Content type of the image stored in the user folder, {@code null} when nothing is stored. */
    private final String storedContentType;

    public OicAvatarProperty(@CheckForNull AvatarImage avatarImage) {
        this.avatarImage = avatarImage;
        this.storedContentType = null;
    }

    /**
     * Stores the image in the user's folder so that Jenkins, rather than a third party, serves it.
     */
    OicAvatarProperty(@NonNull User user, @NonNull AvatarData avatarData) throws IOException {
        this.avatarImage = null;
        this.storedContentType = avatarData.contentType();
        File avatarFile = avatarFile(user);
        if (avatarFile == null) {
            throw new IOException("Unable to store the avatar as the user folder is unavailable");
        }
        Files.write(avatarFile.toPath(), avatarData.bytes());
    }

    public String getAvatarUrl() {
        return getAvatarUrlForUser(user);
    }

    public String getAvatarUrlForUser(@CheckForNull User avatarUser) {
        if (!isHasAvatar()) {
            return null;
        }
        if (storedContentType != null || avatarImage.isDataUrl()) {
            if (avatarUser == null) {
                return null;
            }
            String userUrl = avatarUser.getUrl();
            if (!userUrl.endsWith("/")) {
                userUrl += "/";
            }
            return userUrl + getUrlName() + "/image";
        }
        return avatarImage.url;
    }

    public boolean isHasAvatar() {
        if (storedContentType != null) {
            File avatarFile = avatarFile(user);
            return avatarFile != null && avatarFile.isFile();
        }
        return avatarImage != null && avatarImage.isValid();
    }

    public String getDisplayName() {
        return "OpenID Connect Avatar";
    }

    public String getIconFileName() {
        return null;
    }

    public String getUrlName() {
        return AVATAR_FILE_NAME;
    }

    public void doImage(StaplerResponse2 response) throws IOException {
        File avatarFile = storedContentType == null ? null : avatarFile(user);
        if (avatarFile != null && avatarFile.isFile()) {
            response.setHeader("X-Content-Type-Options", "nosniff");
            try (InputStream input = Files.newInputStream(avatarFile.toPath())) {
                response.serveFile(
                        Stapler.getCurrentRequest2(),
                        input,
                        avatarFile.lastModified(),
                        avatarFile.length(),
                        storedContentType);
            } catch (ServletException e) {
                throw new IOException("Unable to serve avatar", e);
            }
            return;
        }
        AvatarData data = avatarImage == null ? null : parseDataUrl(avatarImage.url);
        if (data == null) {
            response.sendError(404);
            return;
        }
        response.setContentType(data.contentType());
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.getOutputStream().write(data.bytes());
    }

    @CheckForNull
    private static File avatarFile(@CheckForNull User user) {
        File userFolder = user == null ? null : user.getUserFolder();
        return userFolder == null ? null : new File(userFolder, AVATAR_FILE_NAME);
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
    @SuppressRestrictedWarnings(AvatarContributor.class)
    public static class AvatarImage {
        static final int MAX_SIZE = 5 * 1024 * 1024;

        private final String url;

        public AvatarImage(String url) {
            this.url = url;
            AvatarContributor.allow(url);
        }

        public boolean isDataUrl() {
            return url != null && url.startsWith("data:");
        }

        public boolean isValid() {
            return url != null && (!isDataUrl() || parseDataUrl(url) != null);
        }

        private Object readResolve() {
            AvatarContributor.allow(url);
            return this;
        }
    }

    /** An avatar image that has been decoded and validated. */
    record AvatarData(String contentType, byte[] bytes) {
        static final Set<String> SUPPORTED_CONTENT_TYPES = Set.of("image/gif", "image/jpeg", "image/png", "image/webp");
    }

    @CheckForNull
    static AvatarData parseDataUrl(@CheckForNull String dataUrl) {
        if (dataUrl == null || !dataUrl.startsWith("data:")) {
            return null;
        }
        int separator = dataUrl.indexOf(',');
        if (separator <= 5 || separator == dataUrl.length() - 1) {
            return null;
        }
        String metadata = dataUrl.substring(5, separator);
        if (!metadata.endsWith(";base64")) {
            return null;
        }
        int metadataSeparator = metadata.indexOf(';');
        String contentType = metadata.substring(0, metadataSeparator);
        if (!metadata.equals(contentType + ";base64")) {
            return null;
        }
        if (!AvatarData.SUPPORTED_CONTENT_TYPES.contains(contentType)) {
            return null;
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(dataUrl.substring(separator + 1));
            return bytes.length > AvatarImage.MAX_SIZE ? null : new AvatarData(contentType, bytes);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

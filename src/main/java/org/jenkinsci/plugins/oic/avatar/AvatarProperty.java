package org.jenkinsci.plugins.oic.avatar;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.Action;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.security.csp.AvatarContributor;
import jenkins.util.SystemProperties;
import net.sf.json.JSONObject;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;

/**
 * Records the avatar of a user that logged in through OpenID Connect.
 *
 * <p>
 * Depending on the configured strategy this either holds the {@code picture} claim URL for the browser to fetch
 * directly from the identity provider ({@link #url}), or metadata for a copy that Jenkins downloaded and stores in the
 * user's folder ({@link #cached}).
 * <p>
 * This property {@link Action implements Action} purely so that the cached image gets a URL:
 * {@link User#getPropertyActions()} collects the {@link UserProperty} instances that are also {@link Action}s, and
 * {@link User#getDynamic(String)} routes requests to them by {@link #getUrlName()}. That is what makes
 * {@code /user/<id>/oic-avatar/image} reach {@link #doImage}.
 * <p>
 * This class supersedes {@code org.jenkinsci.plugins.oic.OicAvatarProperty}; see {@link #addCompatibilityAliases()}.
 */
@SuppressRestrictedWarnings(AvatarContributor.class)
public class AvatarProperty extends UserProperty implements Action {

    private static final Logger LOGGER = Logger.getLogger(AvatarProperty.class.getName());

    /** base name of the cached image file inside the user's folder. */
    static final String FILE_BASE_NAME = "oic-avatar";

    /** the URL segment under {@code /user/<id>/} that {@link #doImage} is served from. */
    static final String URL_NAME = "oic-avatar";

    /** how long a downloaded avatar is considered fresh before we re-download it. */
    @SuppressWarnings("boxing")
    public static final long CACHE_TTL_MS = SystemProperties.getLong(
            "OIC_AVATAR_CACHE_TTL_MS", Duration.ofHours(24).toMillis());

    /** how long the browser may cache the image we serve. */
    private static final long EXPIRATION_MS = Duration.ofHours(1).toMillis();

    /** provider URL for the browser to fetch directly; null unless in serve-from-provider mode */
    @CheckForNull
    private String url;

    /** metadata for the copy cached in the user's folder; null unless Jenkins downloaded it */
    @CheckForNull
    private CachedAvatar cached;

    /**
     * @deprecated superseded by {@link #url}; retained only so pre-relocation config.xml still loads
     */
    @Deprecated
    private transient AvatarImage avatarImage;

    /** the "empty / cleared" instance. */
    AvatarProperty() {}

    AvatarProperty(@CheckForNull String url) {
        this.url = url;
    }

    AvatarProperty(@NonNull CachedAvatar cached) {
        this.cached = cached;
    }

    private Object readResolve() {
        // 1. migrate pre-relocation data
        if (avatarImage != null) {
            if (url == null) {
                url = avatarImage.url;
            }
            avatarImage = null;
        }
        // 2. re-register the domain for CSP after loading from disk (this preserves the fix in commit f270dc9)
        if (url != null) {
            AvatarContributor.allow(url);
        }
        // 3. nothing left to represent -> remove ourselves from the user.
        //    hudson.model.User.fixUpAfterLoad() calls removeNullsThatFailedToLoad()
        //    (properties.removeIf(Objects::isNull)) before anything else, so returning null here is
        //    a supported way for a UserProperty to delete itself on load. There is no
        //    User.removeProperty() API, so this is how a cleared avatar finally leaves config.xml.
        if (url == null && cached == null) {
            return null;
        }
        return this;
    }

    /**
     * Register the pre-relocation class name so existing {@code users/<id>/config.xml} still loads.
     * No alias is needed for the nested {@link AvatarImage}: XStream only writes a {@code class=}
     * attribute when the runtime type differs from the declared field type, and it does not here.
     */
    @Initializer(before = InitMilestone.PLUGINS_STARTED)
    public static void addCompatibilityAliases() {
        User.XSTREAM.addCompatibilityAlias("org.jenkinsci.plugins.oic.OicAvatarProperty", AvatarProperty.class);
    }

    /**
     * Whether the cached image was downloaded from the given claim URL and is still within the cache TTL.
     *
     * @param claimUrl the {@code picture} claim URL from the current login
     * @return {@code true} if there is nothing to do, {@code false} if the avatar should be (re-)downloaded
     */
    public boolean isFreshFor(@NonNull String claimUrl) {
        if (cached == null || !claimUrl.equals(cached.getSourceUrl())) {
            return false;
        }
        File file = getImageFile();
        if (file == null || !file.isFile()) {
            return false;
        }
        return System.currentTimeMillis() - cached.getLastModified() < CACHE_TTL_MS;
    }

    /**
     * The URL the browser should load the avatar from, either at the identity provider or on this Jenkins.
     *
     * @return the URL, or {@code null} if there is no avatar (or no usable Jenkins root URL)
     */
    @CheckForNull
    public String getAvatarUrl() {
        if (url != null) {
            return url;
        }
        if (cached == null || user == null) {
            return null;
        }
        String root = rootUrl();
        if (root == null) {
            // without a root URL we can only produce a broken link, so claim we have no avatar
            return null;
        }
        // /<root>/user/<id>/oic-avatar/image?t=<lastModified> -- the timestamp busts browser caches
        // when the image changes behind an unchanged provider URL.
        return root + user.getUrl() + "/" + URL_NAME + "/image?t=" + cached.getLastModified();
    }

    /**
     * The Jenkins root URL, which always ends with {@code /} ({@link User#getUrl()} has no leading slash).
     */
    @CheckForNull
    private static String rootUrl() {
        return Stapler.getCurrentRequest2() != null
                ? Jenkins.get().getRootUrlFromRequest()
                : Jenkins.get().getRootUrl();
    }

    @Override
    @NonNull
    public String getDisplayName() {
        return Messages.AvatarProperty_DisplayName();
    }

    /** no icon: the avatar must not show up in the user's sidebar. */
    @Override
    @CheckForNull
    public String getIconFileName() {
        return null;
    }

    @Override
    @NonNull
    public String getUrlName() {
        return URL_NAME;
    }

    /**
     * The property is not user-editable, so a user configuration form submit must never be able to change or wipe it.
     * We therefore deliberately do not bind the submitted JSON and simply keep the existing instance.
     */
    @Override
    public UserProperty reconfigure(StaplerRequest2 req, JSONObject form) throws Descriptor.FormException {
        return this;
    }

    /**
     * The cached image file, or {@code null} if there is none / the user has no folder yet.
     */
    @Restricted(NoExternalUse.class)
    @CheckForNull
    public File getImageFile() {
        if (cached == null || user == null) {
            return null;
        }
        File folder = user.getUserFolder(); // @CheckForNull, null until the user has been saved
        return folder == null ? null : new File(folder, FILE_BASE_NAME + "." + cached.getFileExtension());
    }

    /**
     * Serves the cached avatar image. No extra permission check: reaching {@code /user/<id>/} already
     * requires Jenkins.READ, the same bar as the pages that render avatars.
     */
    @Restricted(NoExternalUse.class)
    public void doImage(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException, ServletException {
        File file = getImageFile();
        if (cached == null || file == null || !file.isFile()) {
            rsp.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        // the browser must not be allowed to re-interpret the bytes as something other than the
        // image type we sniffed at download time
        rsp.setHeader("X-Content-Type-Options", "nosniff");
        rsp.setContentType(cached.getContentType());
        try (InputStream in = Files.newInputStream(file.toPath())) {
            rsp.serveFile(
                    req,
                    in,
                    cached.getLastModified(),
                    EXPIRATION_MS,
                    cached.getLength(),
                    FILE_BASE_NAME + "." + cached.getFileExtension());
        }
    }

    /**
     * Record that the browser should fetch the avatar straight from the identity provider.
     *
     * @param user the user to record the avatar against
     * @param url the {@code picture} claim URL
     */
    public static void serveFromUrl(@NonNull User user, @NonNull String url) throws IOException {
        deleteCachedFiles(user, null); // switching away from a download mode must not orphan files
        AvatarContributor.allow(url);
        user.addProperty(new AvatarProperty(url));
    }

    /**
     * Remove any avatar for the user, so that the UI falls back to Jenkins' default person icon.
     */
    public static void clear(@NonNull User user) throws IOException {
        deleteCachedFiles(user, null);
        AvatarProperty existing = user.getProperty(AvatarProperty.class);
        if (existing != null && (existing.url != null || existing.cached != null)) {
            // core has no User.removeProperty(); persist an empty property now and readResolve()
            // will drop the element entirely the next time the user is loaded.
            user.addProperty(new AvatarProperty());
        }
    }

    /**
     * Store a downloaded avatar in the user's folder and record it against the user.
     *
     * @param user the user the avatar belongs to
     * @param sourceUrl the claim URL the image was downloaded from
     * @param type the sniffed image type
     * @param data the image content
     */
    static void store(
            @NonNull User user, @NonNull String sourceUrl, @NonNull AvatarImageType type, @NonNull byte[] data)
            throws IOException {
        File folder = user.getUserFolder();
        if (folder == null) {
            // the folder only exists once the user record has been saved
            user.save();
            folder = user.getUserFolder();
        }
        if (folder == null) {
            LOGGER.warning(() ->
                    "Not storing the avatar for user " + user.getId() + " as the user folder could not be created");
            return;
        }
        Path target = new File(folder, FILE_BASE_NAME + "." + type.getFileExtension()).toPath();
        Path temp = Files.createTempFile(folder.toPath(), FILE_BASE_NAME, ".tmp");
        try {
            Files.write(temp, data);
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            // a successful move already removed the temp file; this only cleans up after a failure
            try {
                Files.deleteIfExists(temp);
            } catch (IOException e) {
                LOGGER.log(Level.FINE, e, () -> "Could not delete temporary avatar file " + temp);
            }
        }
        // the image may previously have been stored in a different format
        deleteCachedFiles(user, type.getFileExtension());
        user.addProperty(new AvatarProperty(new CachedAvatar(
                sourceUrl, type.getContentType(), type.getFileExtension(), data.length, System.currentTimeMillis())));
    }

    /**
     * Delete the cached avatar files of the user.
     *
     * @param user the user whose files should be deleted
     * @param keepExtension a file extension to keep, or {@code null} to delete all of them
     */
    private static void deleteCachedFiles(@NonNull User user, @CheckForNull String keepExtension) {
        File folder = user.getUserFolder();
        if (folder == null) {
            return;
        }
        for (AvatarImageType type : AvatarImageType.values()) {
            String extension = type.getFileExtension();
            if (extension.equals(keepExtension)) {
                continue;
            }
            Path path = new File(folder, FILE_BASE_NAME + "." + extension).toPath();
            try {
                Files.deleteIfExists(path);
            } catch (IOException e) {
                LOGGER.log(Level.FINE, e, () -> "Could not delete cached avatar file " + path);
            }
        }
    }

    /**
     * Metadata for an avatar image cached under {@link User#getUserFolder()}.
     */
    public static class CachedAvatar {

        private final String sourceUrl;
        private final String contentType;
        private final String fileExtension;
        private final long length;
        private final long lastModified;

        public CachedAvatar(
                String sourceUrl, String contentType, String fileExtension, long length, long lastModified) {
            this.sourceUrl = sourceUrl;
            this.contentType = contentType;
            this.fileExtension = fileExtension;
            this.length = length;
            this.lastModified = lastModified;
        }

        /** the claim URL the image was downloaded from. */
        public String getSourceUrl() {
            return sourceUrl;
        }

        /** the MIME type to serve the image as, from {@link AvatarImageType#getContentType()}. */
        public String getContentType() {
            return contentType;
        }

        /** the extension of the file in the user's folder, from {@link AvatarImageType#getFileExtension()}. */
        public String getFileExtension() {
            return fileExtension;
        }

        /** the size of the image in bytes. */
        public long getLength() {
            return length;
        }

        /** when the image was downloaded. */
        public long getLastModified() {
            return lastModified;
        }
    }

    /**
     * @deprecated only used to read pre-relocation {@code config.xml}; see {@link AvatarProperty#url}
     */
    @Deprecated
    public static class AvatarImage {
        /**
         * The field name is load bearing: on disk the data looks like
         * {@code <avatarImage><url>https://...</url></avatarImage>}.
         */
        private String url;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.AvatarProperty_DisplayName();
        }

        /** not user-configurable. */
        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public UserProperty newInstance(User user) {
            // returning null (the old code returned an empty property) keeps core's
            // allocateDefaultPropertyInstancesAsNeeded() from attaching an empty avatar property to
            // every single user, so `user.getProperty(AvatarProperty.class) == null` means "no avatar".
            return null;
        }
    }
}

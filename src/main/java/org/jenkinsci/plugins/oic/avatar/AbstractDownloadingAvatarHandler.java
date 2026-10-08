package org.jenkinsci.plugins.oic.avatar;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.User;
import java.io.IOException;
import org.jenkinsci.plugins.oic.OicSecurityRealm;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Base class for the strategies where the controller downloads the image from the provider and Jenkins
 * then serves it itself.
 * <p>
 * The provider therefore only needs to be reachable from the controller, and no third-party domain is
 * added to the {@code img-src} Content Security Policy directive. In exchange the controller performs
 * the network IO, so the download is done asynchronously (logins are never delayed by it), the result
 * is cached on disk and only refreshed once the cache entry expires.
 * <p>
 * This class is not itself selectable by the administrator; see {@link ServeFromJenkinsAvatarHandler}
 * and {@link ServeFromJenkinsUsingAccessTokenAvatarHandler}.
 */
@Restricted(NoExternalUse.class)
public abstract class AbstractDownloadingAvatarHandler extends AvatarHandler {

    private static final long serialVersionUID = 1L;

    @Override
    public void handleAvatar(@NonNull OicSecurityRealm realm, @NonNull User user, @CheckForNull String avatarUrl)
            throws IOException {
        if (avatarUrl == null) {
            AvatarProperty.clear(user);
            return;
        }
        AvatarProperty existing = user.getProperty(AvatarProperty.class);
        if (existing != null && existing.isFreshFor(avatarUrl)) {
            // same provider URL, file still present, younger than the cache TTL
            return;
        }
        AvatarDownloadService.get()
                .enqueue(user.getId(), avatarUrl, useAccessToken(), realm.isDisableSslVerification());
    }

    /** whether to send the user's OIDC access token as a bearer token when fetching the image */
    protected abstract boolean useAccessToken();
}

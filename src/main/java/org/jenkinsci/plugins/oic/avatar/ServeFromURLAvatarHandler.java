package org.jenkinsci.plugins.oic.avatar;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import java.io.IOException;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.oic.OicSecurityRealm;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Records the URL advertised by the provider as-is, so that each user's browser fetches the image
 * directly from the provider.
 * <p>
 * This is the default, and is the behaviour of this plugin before the avatar strategy became
 * configurable. Because the image is fetched by the browser rather than by the controller, the
 * provider must be reachable from every user's browser, and the provider's domain ends up in the
 * {@code img-src} Content Security Policy directive - which means a third party gets to observe
 * requests originating from your users. It also cannot work with a provider that requires
 * authentication to serve the image.
 */
public class ServeFromURLAvatarHandler extends AvatarHandler {

    private static final long serialVersionUID = 1L;

    @DataBoundConstructor
    public ServeFromURLAvatarHandler() {}

    @Override
    public void handleAvatar(@NonNull OicSecurityRealm realm, @NonNull User user, @CheckForNull String avatarUrl)
            throws IOException {
        if (avatarUrl == null) {
            AvatarProperty.clear(user);
        } else {
            AvatarProperty.serveFromUrl(user, avatarUrl);
        }
    }

    @Extension
    @Symbol("serveFromProvider")
    public static class DescriptorImpl extends Descriptor<AvatarHandler> {

        @Override
        public String getDisplayName() {
            return Messages.ServeFromURLAvatarHandler_DisplayName();
        }
    }
}

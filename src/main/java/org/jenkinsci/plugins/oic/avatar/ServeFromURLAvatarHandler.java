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
 * As the image is fetched by the browser rather than by the controller, the
 * URL must be reachable from every user's browser, and the provider's domain ends up in the
 * {@code img-src} Content Security Policy directive.
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
            user.addProperty(new AvatarProperty(avatarUrl));
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

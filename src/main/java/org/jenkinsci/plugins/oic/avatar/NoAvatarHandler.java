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
 * Ignores the avatar advertised by the provider entirely, and removes any avatar that was previously
 * recorded for the user.
 * <p>
 * Nothing is fetched from the provider, by either the browser or the controller, so no third party is
 * told which users are looking at which Jenkins pages. The trade-off is simply that users see the
 * generic Jenkins avatar instead of their own picture.
 */
public class NoAvatarHandler extends AvatarHandler {

    private static final long serialVersionUID = 1L;

    @DataBoundConstructor
    public NoAvatarHandler() {}

    @Override
    public void handleAvatar(@NonNull OicSecurityRealm realm, @NonNull User user, @CheckForNull String avatarUrl)
            throws IOException {
        // the claim is deliberately ignored, but a previously stored avatar must still be removed
        AvatarProperty.clear(user);
    }

    @Extension
    @Symbol("noAvatar")
    public static class DescriptorImpl extends Descriptor<AvatarHandler> {

        @Override
        public String getDisplayName() {
            return Messages.NoAvatarHandler_DisplayName();
        }
    }
}

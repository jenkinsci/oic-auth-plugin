package org.jenkinsci.plugins.oic.avatar;

import hudson.Extension;
import hudson.model.Descriptor;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Downloads the avatar using the user's OIDC access token as a bearer token, and serves it from
 * Jenkins.
 * <p>
 * Required for providers that refuse to serve an avatar to an unauthenticated request. The access
 * token is only ever sent over {@code https}: if the provider advertises the avatar over plain
 * {@code http} the request is made anonymously instead, rather than putting the token on the wire in
 * clear text, so such a download will usually fail and the user will simply have no avatar. As with
 * {@link ServeFromJenkinsAvatarHandler}, only GIF, JPEG and PNG images are accepted and images of
 * 5&nbsp;MB or more are rejected.
 */
public class ServeFromJenkinsUsingAccessTokenAvatarHandler extends AbstractDownloadingAvatarHandler {

    private static final long serialVersionUID = 1L;

    @DataBoundConstructor
    public ServeFromJenkinsUsingAccessTokenAvatarHandler() {}

    @Override
    protected boolean useAccessToken() {
        return true;
    }

    @Extension
    @Symbol("serveFromJenkinsUsingAccessToken")
    public static class DescriptorImpl extends Descriptor<AvatarHandler> {

        @Override
        public String getDisplayName() {
            return Messages.ServeFromJenkinsUsingAccessTokenAvatarHandler_DisplayName();
        }
    }
}

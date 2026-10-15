package org.jenkinsci.plugins.oic.avatar;

import hudson.Extension;
import hudson.model.Descriptor;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Downloads the avatar with an anonymous request and serves it from Jenkins.
 * <p>
 * Suitable when the provider publishes avatars without requiring authentication but is not reachable
 * from users' browsers - for example a provider that only listens on an internal network. Only GIF,
 * JPEG and PNG images are accepted, and images of 5&nbsp;MB or more are rejected, which bounds what an
 * untrusted provider can make the controller store.
 * <p>
 * If the provider requires the request to be authenticated, use
 * {@link ServeFromJenkinsUsingAccessTokenAvatarHandler} instead.
 */
public class ServeFromJenkinsAvatarHandler extends AbstractDownloadingAvatarHandler {

    private static final long serialVersionUID = 1L;

    @DataBoundConstructor
    public ServeFromJenkinsAvatarHandler() {}

    @Override
    protected boolean useAccessToken() {
        return false;
    }

    @Extension
    @Symbol("serveFromJenkins")
    public static class DescriptorImpl extends Descriptor<AvatarHandler> {

        @Override
        public String getDisplayName() {
            return Messages.ServeFromJenkinsAvatarHandler_DisplayName();
        }
    }
}

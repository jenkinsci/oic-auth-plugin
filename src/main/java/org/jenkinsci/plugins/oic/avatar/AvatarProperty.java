package org.jenkinsci.plugins.oic.avatar;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import java.io.IOException;
import java.util.Objects;
import jenkins.security.csp.AvatarContributor;
import net.sf.json.JSONObject;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.kohsuke.stapler.StaplerRequest2;

/**
 * Records the avatar of a user that logged in through OpenID Connect.
 */
@SuppressRestrictedWarnings(AvatarContributor.class)
public class AvatarProperty extends UserProperty {

    /** Provider URL for the browser to fetch directly */
    @CheckForNull
    private String avatarUrl;

    /** the "empty / cleared" instance. */
    AvatarProperty() {}

    AvatarProperty(String avatarUrl) {
        this.avatarUrl = avatarUrl;
        AvatarContributor.allow(avatarUrl);
    }

    private Object readResolve() {
        // allow the image to be downloaded by adding the domain it to the CSP policy
        if (avatarUrl != null) {
            AvatarContributor.allow(avatarUrl);
        }
        return this;
    }

    /**
     * The URL the browser should load the avatar from
     *
     * @return the URL, or {@code null} if there is no avatar.
     */
    @CheckForNull
    public String getAvatarUrl() {
        return avatarUrl;
    }

    /**
     * Clear the AvatarProperty
     * @param user the user to clear the property from.
     */
    public static void clear(User user) throws IOException {
        // there is no removeProperty in User so we just set a property with no URL
        user.addProperty(new AvatarProperty());
    }

    /**
     * The property is not user-editable, so a user configuration form submit must never be able to change or wipe it.
     * We therefore deliberately do not bind the submitted JSON and simply keep the existing instance.
     */
    @Override
    public UserProperty reconfigure(StaplerRequest2 req, JSONObject form) throws Descriptor.FormException {
        return this;
    }

    @Override
    public int hashCode() {
        return Objects.hash(avatarUrl);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AvatarProperty other = (AvatarProperty) obj;
        return Objects.equals(avatarUrl, other.avatarUrl);
    }
}

package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.util.Secret;
import java.io.Serializable;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.StaplerRequest;

public class OicCredentials extends UserProperty implements Serializable {
    static final String PROPERTY_NAME = "oicCredentials";

    private static final long serialVersionUID = 1L;

    private final Secret accessToken;
    private final Secret idToken;
    private final Secret refreshToken;
    private final Long expiresAtMillis;

    @Override
    public UserProperty reconfigure(StaplerRequest req, JSONObject form) throws Descriptor.FormException {
        req.bindJSON(this, form);
        return this;
    }

    public OicCredentials(Secret accessToken, Secret idToken, Secret refreshToken, Long expiresAtMillis) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.expiresAtMillis = expiresAtMillis;
    }

    public OicCredentials(
            String accessToken,
            String idToken,
            String refreshToken,
            Long expiresInSeconds,
            Long currentTimestamp,
            Long allowedClockSkewSeconds) {
        this.accessToken = Secret.fromString(accessToken);
        this.idToken = Secret.fromString(idToken);
        this.refreshToken = Secret.fromString(refreshToken);

        if (expiresInSeconds != null && expiresInSeconds > 0) {
            long allowedClockSkewFixed = Util.fixNull(allowedClockSkewSeconds, 60L);
            this.expiresAtMillis = currentTimestamp + (expiresInSeconds + allowedClockSkewFixed) * 1000;
        } else {
            this.expiresAtMillis = null;
        }
    }

    public String getAccessToken() {
        return Secret.toString(accessToken);
    }

    public String getIdToken() {
        return Secret.toString(idToken);
    }

    public String getRefreshToken() {
        return Secret.toString(refreshToken);
    }

    public Long getExpiresAtMillis() {
        return expiresAtMillis;
    }

    @Extension
    @Symbol(PROPERTY_NAME)
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }
    }
}

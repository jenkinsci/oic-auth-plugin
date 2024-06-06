package org.jenkinsci.plugins.oic;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class OicUserProperty extends UserProperty {

    @Extension
    public static class Descriptor extends UserPropertyDescriptor {

        @Override
        public UserProperty newInstance(User user) {
            return null;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }
    }

    private final List<String> authorities = new ArrayList<>();
    /** @deprecated not actually used (implicit in user to which it is attached) */
    @Deprecated
    private final String userName;

    OicUserProperty(String userName, Collection<? extends GrantedAuthority> authorities) {
        this.userName = userName;
        for (GrantedAuthority authority : authorities) {
            this.authorities.add(authority.getAuthority());
        }
    }

    @Override
    public UserProperty reconfigure(StaplerRequest req, JSONObject form) {
        return this;
    }

    public List<String> getAuthorities() {
        return Collections.unmodifiableList(authorities);
    }

    public List<GrantedAuthority> getAuthoritiesAsGrantedAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String auth : this.authorities) authorities.add(new SimpleGrantedAuthority(auth));

        return authorities;
    }

    public String getAllGrantedAuthorities() {
        StringBuilder result = new StringBuilder();
        result.append("Number of GrantedAuthorities in OicUserProperty for ")
                .append(userName)
                .append(": ")
                .append(authorities.size());
        for (String authority : authorities) {
            result.append("<br>\nAuthority: ").append(authority);
        }
        return result.toString();
    }

    public String getUserName() {
        return userName;
    }
}

package org.jenkinsci.plugins.oic;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class OicUserDetails implements UserDetails {
    private static final long serialVersionUID = 1L;

    private final String userName;
    private final List<GrantedAuthority> grantedAuthorities;

    public OicUserDetails(String userName, Collection<? extends GrantedAuthority> grantedAuthorities) {
        this.userName = userName;
        this.grantedAuthorities = new ArrayList<>(grantedAuthorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        // OpenID Connect => no passwords...
        return null;
    }

    @Override
    public String getUsername() {
        return this.userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

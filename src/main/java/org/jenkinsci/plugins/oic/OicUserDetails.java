package org.jenkinsci.plugins.oic;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

import java.util.Arrays;

public class OicUserDetails implements UserDetails {
    private static final long serialVersionUID = 1L;

    private final String userName;
    private final GrantedAuthority[] grantedAuthorities;

    public OicUserDetails(String userName, GrantedAuthority[] grantedAuthorities) {
        this.userName = userName;
        this.grantedAuthorities = Arrays.copyOf(grantedAuthorities, grantedAuthorities.length);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return Arrays.copyOf(grantedAuthorities, grantedAuthorities.length);
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

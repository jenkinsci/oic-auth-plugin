package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class OicUserDetailsTest {

    private OicUserDetails details;

    private String userName = "fred";

    private SimpleGrantedAuthority admin = new SimpleGrantedAuthority("admin");

    private SimpleGrantedAuthority read = new SimpleGrantedAuthority("read");

    private List<GrantedAuthority> grantedAuthorities = Arrays.asList(admin, read);

    @BeforeEach
    void init() {
        details = new OicUserDetails(userName, grantedAuthorities);
    }

    @Test
    void testGetAuthorities() {
        assertThat(details.getAuthorities(), containsInAnyOrder(admin, read));
    }

    @Test
    void testGetPassword() {
        // OpenID Connect => no passwords...
        assertNull(details.getPassword());
    }

    @Test
    void testGetUsername() {
        assertEquals(userName, details.getUsername());
    }

    @Test
    void TestIsAccountNonExpired() {
        assertTrue(details.isAccountNonExpired());
    }

    @Test
    void TestIsAccountNonLocked() {
        assertTrue(details.isAccountNonLocked());
    }

    @Test
    void TestIsCredentialsNonExpired() {
        assertTrue(details.isCredentialsNonExpired());
    }

    @Test
    void TestIsEnabled() {
        assertTrue(details.isEnabled());
    }
}

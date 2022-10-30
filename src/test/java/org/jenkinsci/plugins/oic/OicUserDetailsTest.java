package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.junit.Before;
import org.junit.Test;
import java.util.Arrays;
import java.util.List;

public class OicUserDetailsTest {

    private OicUserDetails details;

    private String userName = "fred";

    private SimpleGrantedAuthority admin = new SimpleGrantedAuthority("admin");

    private SimpleGrantedAuthority read = new SimpleGrantedAuthority("read");

    private List<GrantedAuthority> grantedAuthorities = Arrays.asList(admin, read);

    @Before
    public void init() {
        details = new OicUserDetails(userName, grantedAuthorities);
    }

    @Test
    public void testGetAuthorities() {
        assertThat(details.getAuthorities(), containsInAnyOrder(admin, read));
    }

    @Test
    public void testGetPassword() {
        // OpenID Connect => no passwords...
        assertNull(details.getPassword());
    }

    @Test
    public void testGetUsername() {
        assertEquals(userName, details.getUsername());
    }

    @Test
    public void TestIsAccountNonExpired() {
        assertTrue(details.isAccountNonExpired());
    }

    @Test
    public void TestIsAccountNonLocked() {
        assertTrue(details.isAccountNonLocked());
    }

    @Test
    public void TestIsCredentialsNonExpired() {
        assertTrue(details.isCredentialsNonExpired());
    }

    @Test
    public void TestIsEnabled() {
        assertTrue(details.isEnabled());
    }
}

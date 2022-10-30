package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.junit.Test;
import java.util.List;
import java.util.Arrays;

public class OicUserPropertyTest {

    public static final String ADMIN = "admin";

    public static final String READ = "read";

    private static final SimpleGrantedAuthority GRANTED_AUTH1 = new SimpleGrantedAuthority(ADMIN);

    private static final SimpleGrantedAuthority GRANTED_AUTH2 = new SimpleGrantedAuthority(READ);

    private OicUserProperty userProp;

    @Test
    public void testGetAllGrantedAuthorities() {
        String userName = "derek";
        List<GrantedAuthority> authorities = Arrays.asList(GRANTED_AUTH1, GRANTED_AUTH2);

        userProp = new OicUserProperty(userName, authorities);

        StringBuilder result = new StringBuilder();
        result.append("Number of GrantedAuthorities in OicUserProperty for ").append(userName).append(": ")
            .append(authorities.size());
        for (GrantedAuthority authority : authorities) {
            result.append("<br>\nAuthority: ").append(authority.getAuthority());
        }
        String expectedAuthString =  result.toString();

        assertEquals(expectedAuthString, userProp.getAllGrantedAuthorities());
    }

    @Test
    public void testGetAuthorities() {
        String userName = "derek";
        List<GrantedAuthority> authorities = Arrays.asList(GRANTED_AUTH1, GRANTED_AUTH2);

        userProp = new OicUserProperty(userName, authorities);

        assertThat(userProp.getAuthorities(), containsInAnyOrder(READ, ADMIN));
    }

    @Test
    public void testGetDescriptor() {
        String userName = "derek";
        List<GrantedAuthority> authorities = Arrays.asList(GRANTED_AUTH1, GRANTED_AUTH2);

        userProp = new OicUserProperty(userName, authorities);

        assertNotNull(userProp.getDescriptor());
    }
}

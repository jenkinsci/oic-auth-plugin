package org.jenkinsci.plugins.oic;

import static org.junit.Assert.assertEquals;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.junit.Test;

public class OicUserPropertyTest {

    private static final GrantedAuthorityImpl AUTH1 = new GrantedAuthorityImpl("admin");

    private static final GrantedAuthorityImpl AUTH2 = new GrantedAuthorityImpl("admin");

    private OicUserProperty userProp;

    @Test
    public void testGetAllGrantedAuthorities() {
        String userName = "derek";
        GrantedAuthority[] authorities = new GrantedAuthority[]{AUTH1, AUTH2};
        userProp = new OicUserProperty(userName, authorities);

        StringBuilder result = new StringBuilder();
        result.append("Number of GrantedAuthorities in OicUserProperty for ").append(userName).append(": ")
            .append(authorities.length);
        for (GrantedAuthority authority : authorities) {
            result.append("<br>\nAuthority: ").append(authority.getAuthority());
        }
        String expectedAuthString =  result.toString();

        assertEquals(expectedAuthString, userProp.getAllGrantedAuthorities());
    }
}

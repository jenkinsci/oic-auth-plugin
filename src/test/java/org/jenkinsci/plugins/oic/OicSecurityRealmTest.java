package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.util.Secret;
import java.io.IOException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class OicSecurityRealmTest {

    public static final String ADMIN = "admin";

    private static final GrantedAuthorityImpl GRANTED_AUTH1 = new GrantedAuthorityImpl(ADMIN);

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(), true);

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void testAuthenticate_withAnonymousAuthenticationToken() throws Exception {
        TestRealm realm = new TestRealm(wireMockRule);
        AuthenticationManager manager = realm.getSecurityComponents().manager;

        assertNotNull(manager);

        String key = "testKey";
        Object principal = "testUser";
        GrantedAuthority[] authorities = new GrantedAuthority[]{GRANTED_AUTH1};
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(key, principal, authorities);

        assertEquals(token, manager.authenticate(token));
    }

    @Test(expected = BadCredentialsException.class)
    public void testAuthenticate_withUsernamePasswordAuthenticationToken() throws Exception {
        TestRealm realm = new TestRealm(wireMockRule);
        AuthenticationManager manager = realm.getSecurityComponents().manager;

        assertNotNull(manager);

        String key = "testKey";
        Object principal = "testUser";
        GrantedAuthority[] authorities = new GrantedAuthority[]{GRANTED_AUTH1};
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(key, principal,
            authorities);

        assertEquals(token, manager.authenticate(token));
    }

    @Test
    public void testGetAuthenticationGatewayUrl() throws IOException {
        TestRealm realm = new TestRealm(wireMockRule);
        assertEquals("securityRealm/escapeHatch", realm.getAuthenticationGatewayUrl());
    }

    @Test
    public void testShouldSetNullClientSecretWhenSecretIsNull() throws IOException {
        TestRealm realm = new TestRealm.Builder(wireMockRule)
            .WithMinimalDefaults()
            .WithClient("id without secret", null)
            .build();
        assertEquals("none", Secret.toString(realm.getClientSecret()));
    }

    @Test
    public void testShouldSetNullClientSecretWhenSecretIsNone() throws IOException {
        TestRealm realm = new TestRealm.Builder(wireMockRule)
            .WithMinimalDefaults()
            .WithClient("id with none secret", "NoNE")
            .build();
        assertEquals("none", Secret.toString(realm.getClientSecret()));
    }
}

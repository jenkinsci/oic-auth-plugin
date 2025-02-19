package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithJenkins
class OicSecurityRealmTest {

    public static final String ADMIN = "admin";

    private static final SimpleGrantedAuthority GRANTED_AUTH1 = new SimpleGrantedAuthority(ADMIN);

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort())
            .build();

    @Test
    void testAuthenticate_withAnonymousAuthenticationToken(JenkinsRule jenkinsRule) throws Exception {
        TestRealm realm = new TestRealm(wireMock);
        AuthenticationManager manager = realm.getSecurityComponents().manager2;

        assertNotNull(manager);

        String key = "testKey";
        Object principal = "testUser";
        Collection<GrantedAuthority> authorities = List.of(GRANTED_AUTH1);
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(key, principal, authorities);

        assertEquals(token, manager.authenticate(token));
    }

    @Test
    void testAuthenticate_withUsernamePasswordAuthenticationToken(JenkinsRule jenkinsRule) throws Exception {
        TestRealm realm = new TestRealm(wireMock);
        AuthenticationManager manager = realm.getSecurityComponents().manager2;
        assertNotNull(manager);
        String key = "testKey";
        Object principal = "testUser";
        Collection<GrantedAuthority> authorities = List.of(GRANTED_AUTH1);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(key, principal, authorities);
        assertThrows(BadCredentialsException.class, () -> assertEquals(token, manager.authenticate(token)));
    }

    @Test
    void testGetAuthenticationGatewayUrl(JenkinsRule jenkinsRule) throws Exception {
        TestRealm realm = new TestRealm(wireMock);
        assertEquals("securityRealm/escapeHatch", realm.getAuthenticationGatewayUrl());
    }

    @Test
    void testShouldSetNullClientSecretWhenSecretIsNull(JenkinsRule jenkinsRule) throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults().WithClient("id without secret", null).build();
        assertEquals("none", Secret.toString(realm.getClientSecret()));
    }

    @Test
    void testGetValidRedirectUrl(JenkinsRule jenkinsRule) throws Exception {
        // root url is http://localhost:????/jenkins/
        final String rootUrl = jenkinsRule.jenkins.getRootUrl();

        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        assertEquals(rootUrl + "foo", realm.getValidRedirectUrl("foo"));
        assertEquals(rootUrl + "foo", realm.getValidRedirectUrl("/jenkins/foo"));
        assertEquals(rootUrl + "foo", realm.getValidRedirectUrl(rootUrl + "foo"));
        assertEquals(rootUrl, realm.getValidRedirectUrl(null));
        assertEquals(rootUrl, realm.getValidRedirectUrl(""));

        assertEquals(rootUrl, realm.getValidRedirectUrl(OicLogoutAction.POST_LOGOUT_URL));
    }

    @Test
    void testShouldReturnRootUrlWhenRedirectUrlIsInvalid(JenkinsRule jenkinsRule) throws Exception {
        // root url is http://localhost:????/jenkins/
        String rootUrl = jenkinsRule.jenkins.getRootUrl();

        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        assertEquals(rootUrl, realm.getValidRedirectUrl("/bar"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("../bar"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("http://localhost/"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("http://localhost/bar/"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("http://localhost/jenkins/../bar/"));
    }

    @Test
    void testShouldCheckEscapeHatchWithPlainPassword(JenkinsRule jenkinsRule) throws Exception {
        final String escapeHatchUsername = "aUsername";
        final String escapeHatchPassword = "aSecretPassword";

        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithEscapeHatch(true, escapeHatchUsername, escapeHatchPassword, "Group")
                        .build();

        assertEquals(escapeHatchUsername, realm.getEscapeHatchUsername());
        assertNotEquals(escapeHatchPassword, Secret.toString(realm.getEscapeHatchSecret()));
        assertTrue(realm.doCheckEscapeHatch(escapeHatchUsername, escapeHatchPassword));
        assertFalse(realm.doCheckEscapeHatch("otherUsername", escapeHatchPassword));
        assertFalse(realm.doCheckEscapeHatch(escapeHatchUsername, "wrongPassword"));
    }

    @Test
    void testShouldCheckEscapeHatchWithHashedPassword(JenkinsRule jenkinsRule) throws Exception {
        final String escapeHatchUsername = "aUsername";
        final String escapeHatchPassword = "aSecretPassword";
        final String escapeHatchCryptedPassword = BCrypt.hashpw(escapeHatchPassword, BCrypt.gensalt());

        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithEscapeHatch(true, escapeHatchUsername, escapeHatchCryptedPassword, "Group")
                        .build();

        assertEquals(escapeHatchUsername, realm.getEscapeHatchUsername());
        assertEquals(escapeHatchCryptedPassword, Secret.toString(realm.getEscapeHatchSecret()));
        assertTrue(realm.doCheckEscapeHatch(escapeHatchUsername, escapeHatchPassword));
        assertFalse(realm.doCheckEscapeHatch("otherUsername", escapeHatchPassword));
        assertFalse(realm.doCheckEscapeHatch(escapeHatchUsername, "wrongPassword"));
    }

    @Test
    public void testHandleTokenExpiration_logoutRequestUri() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        MockHttpServletRequest request = new MockHttpServletRequest() {
            @Override
            public String getRequestURI() {
                return "/logout";
            }
        };
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertTrue(realm.isLogoutRequest(request));
        assertTrue(realm.handleTokenExpiration(request, response));
    }

    @Test
    public void testHandleTokenExpiration_noAuthenticationOrAnonymous() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        SecurityContextHolder.getContext().setAuthentication(null);
        assertFalse(realm.isLogoutRequest(request));
        assertTrue(realm.isNotAuthenticatedOrAnonymous(null));
        assertTrue(realm.handleTokenExpiration(request, response));

        String key = "testKey";
        Object principal = "testUser";

        List<org.springframework.security.core.GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        org.springframework.security.authentication.AnonymousAuthenticationToken token =
                new org.springframework.security.authentication.AnonymousAuthenticationToken(
                        key, principal, grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(token);

        assertFalse(realm.isLogoutRequest(request));
        assertTrue(realm.isNotAuthenticatedOrAnonymous(token));
        assertTrue(realm.handleTokenExpiration(request, response));
    }

    @Test
    public void testHandleTokenExpiration_noOicCredentials(JenkinsRule jenkinsRule) throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertFalse(realm.isLogoutRequest(request));
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        assertFalse(realm.isNotAuthenticatedOrAnonymous(a));

        jenkinsRule.jenkins.getUser(a.getName());
        User user = User.get2(a);
        assertNotNull(user);
        assertNull(user.getProperty(OicCredentials.class));
        assertTrue(realm.handleTokenExpiration(request, response));
    }

    @Test
    public void testIsValidApiTokenRequest_NoTokenAccessWithoutOicSession(JenkinsRule jenkinsRule) throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        MockHttpServletRequest request = new MockHttpServletRequest();
        assertFalse(realm.isLogoutRequest(request));

        List<org.springframework.security.core.GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken("test-user", "", grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(token);

        assertFalse(realm.isNotAuthenticatedOrAnonymous(token));

        jenkinsRule.jenkins.getUser(token.getName());
        User user = User.get2(token);
        assertNotNull(user);
        user.addProperty(new OicCredentials("test", "test", "test", 1L, 1L, 1L));
        assertNotNull(user.getProperty(OicCredentials.class));
        assertFalse(realm.isValidApiTokenRequest(request, user));
    }
}

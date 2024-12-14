package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.util.Secret;
import java.util.Map;
import java.util.Set;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.crypto.bcrypt.BCrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
        GrantedAuthority[] authorities = new GrantedAuthority[] {GRANTED_AUTH1};
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
        GrantedAuthority[] authorities = new GrantedAuthority[] {GRANTED_AUTH1};
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(key, principal, authorities);

        assertEquals(token, manager.authenticate(token));
    }

    @Test
    public void testGetAuthenticationGatewayUrl() throws Exception {
        TestRealm realm = new TestRealm(wireMockRule);
        assertEquals("securityRealm/escapeHatch", realm.getAuthenticationGatewayUrl());
    }

    @Test
    public void testShouldSetNullClientSecretWhenSecretIsNull() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults().WithClient("id without secret", null).build();
        assertEquals("none", Secret.toString(realm.getClientSecret()));
    }

    @Test
    public void testGetValidRedirectUrl() throws Exception {
        // root url is http://localhost:????/jenkins/
        final String rootUrl = jenkinsRule.jenkins.getRootUrl();

        TestRealm realm =
                new TestRealm.Builder(wireMockRule).WithMinimalDefaults().build();

        assertEquals(rootUrl + "foo", realm.getValidRedirectUrl("foo"));
        assertEquals(rootUrl + "foo", realm.getValidRedirectUrl("/jenkins/foo"));
        assertEquals(rootUrl + "foo", realm.getValidRedirectUrl(rootUrl + "foo"));
        assertEquals(rootUrl, realm.getValidRedirectUrl(null));
        assertEquals(rootUrl, realm.getValidRedirectUrl(""));

        assertEquals(rootUrl, realm.getValidRedirectUrl(OicLogoutAction.POST_LOGOUT_URL));
    }

    @Test
    public void testShouldReturnRootUrlWhenRedirectUrlIsInvalid() throws Exception {
        // root url is http://localhost:????/jenkins/
        String rootUrl = jenkinsRule.jenkins.getRootUrl();

        TestRealm realm =
                new TestRealm.Builder(wireMockRule).WithMinimalDefaults().build();

        assertEquals(rootUrl, realm.getValidRedirectUrl("/bar"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("../bar"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("http://localhost/"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("http://localhost/bar/"));
        assertEquals(rootUrl, realm.getValidRedirectUrl("http://localhost/jenkins/../bar/"));
    }

    @Test
    public void testShouldCheckEscapeHatchWithPlainPassword() throws Exception {
        final String escapeHatchUsername = "aUsername";
        final String escapeHatchPassword = "aSecretPassword";

        TestRealm realm = new TestRealm.Builder(wireMockRule)
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
    public void testShouldCheckEscapeHatchWithHashedPassword() throws Exception {
        final String escapeHatchUsername = "aUsername";
        final String escapeHatchPassword = "aSecretPassword";
        final String escapeHatchCryptedPassword = BCrypt.hashpw(escapeHatchPassword, BCrypt.gensalt());

        TestRealm realm = new TestRealm.Builder(wireMockRule)
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
    public void testGetCustomLoginParameters() throws Exception {
        TestRealm realm =
                new TestRealm.Builder(wireMockRule).WithMinimalDefaults().build();
        Set<String> forbiddenKeys = Set.of("forbidden-key");
        assertEquals(
                Map.of("a", "1", "c", "2"),
                realm.getCustomParametersMap("a=1&b&c= 2 &=no&forbidden-key=test", forbiddenKeys));
    }

    @Test
    public void testMaybeOpenIdLogoutEndpointWithNoCustomLogoutQueryParameters() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults().WithLogout(true, "https://endpoint").build();
        assertEquals(
                "https://endpoint?id_token_hint=my-id-token&post_logout_redirect_uri=https%3A%2F%2Flocalhost",
                realm.maybeOpenIdLogoutEndpoint("my-id-token", "null", "https://localhost"));
        assertEquals(
                "https://endpoint?id_token_hint=my-id-token&post_logout_redirect_uri=https%3A%2F%2Flocalhost",
                realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));
        assertEquals(
                "https://endpoint?id_token_hint=my-id-token&state=test&post_logout_redirect_uri=https%3A%2F%2Flocalhost",
                realm.maybeOpenIdLogoutEndpoint("my-id-token", "test", "https://localhost"));
    }

    @Test
    public void testMaybeOpenIdLogoutEndpointWithCustomLogoutQueryParameters() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults()
                        .WithLogoutQueryParameters(
                                "key1=value1&=drop-me&key2 = with-spaces   &param-only&id_token_hint=overwrite-test-1&post_logout_redirect_uri=overwrite-test-2&state=overwrite-test-3")
                        .WithLogout(true, "https://endpoint")
                        .build();
        String result = realm.maybeOpenIdLogoutEndpoint("my-id-token", "test", "https://localhost");
        assertFalse(result.contains("drop-me"));
        assertFalse(result.contains("overwrite-test"));
        assertEquals(
                "https://endpoint?key1=value1&key2=with-spaces&id_token_hint=my-id-token&state=test&post_logout_redirect_uri=https%3A%2F%2Flocalhost&param-only",
                result);
    }
}

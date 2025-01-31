package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import hudson.util.Secret;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class OicSecurityRealmTest {

    public static final String ADMIN = "admin";

    private static final SimpleGrantedAuthority GRANTED_AUTH1 = new SimpleGrantedAuthority(ADMIN);

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(), true);

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void testAuthenticate_withAnonymousAuthenticationToken() throws Exception {
        TestRealm realm = new TestRealm(wireMockRule);
        AuthenticationManager manager = realm.getSecurityComponents().manager2;

        assertNotNull(manager);

        String key = "testKey";
        Object principal = "testUser";
        Collection<GrantedAuthority> authorities = List.of(GRANTED_AUTH1);
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken(key, principal, authorities);

        assertEquals(token, manager.authenticate(token));
    }

    @Test(expected = BadCredentialsException.class)
    public void testAuthenticate_withUsernamePasswordAuthenticationToken() throws Exception {
        TestRealm realm = new TestRealm(wireMockRule);
        AuthenticationManager manager = realm.getSecurityComponents().manager2;

        assertNotNull(manager);

        String key = "testKey";
        Object principal = "testUser";
        Collection<GrantedAuthority> authorities = List.of(GRANTED_AUTH1);
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
    @WithoutJenkins
    public void testGetCustomLoginParameters() throws Exception {
        TestRealm realm =
                new TestRealm.Builder(wireMockRule).WithMinimalDefaults().build();
        Set<String> forbiddenKeys = Set.of("forbidden-key");

        Map<String, String> unsortedMapExpected = Map.of(
                "b", "%2C",
                "%26test", "2%40%2B+%2C+%3F",
                "a%2Ftest%23", "1",
                "b%2B", "%24other%3Anew",
                "d%3D", "2",
                "e%3F", "");

        OicQueryParameterConfiguration empty = new OicQueryParameterConfiguration("non-empty", "");
        empty.setQueryParamName(null);
        empty.setQueryParamValue(null);

        Map<String, String> unsortedMapResult = realm.getCustomParametersMap(
                List.of(
                        new OicQueryParameterConfiguration("a/test#", "1"),
                        new OicQueryParameterConfiguration("b", ","),
                        new OicQueryParameterConfiguration("b+", "$other:new"),
                        new OicQueryParameterConfiguration("&test", " 2@+ , ?"),
                        new OicQueryParameterConfiguration("d=", " 2 "),
                        new OicQueryParameterConfiguration(" e? ", "     "),
                        empty,
                        new OicQueryParameterConfiguration("forbidden-key", "test")),
                forbiddenKeys);
        assertEquals(new TreeMap<>(unsortedMapExpected), new TreeMap<>(unsortedMapResult));
    }

    @Test
    @WithoutJenkins
    public void testMaybeOpenIdLogoutEndpoint() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults()
                        .WithLogout(Boolean.FALSE, "https://endpoint")
                        .build();
        assertNull(realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));

        realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults().WithLogout(Boolean.TRUE, null).build();
        assertNull(realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));

        realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults().WithLogout(Boolean.FALSE, null).build();
        assertNull(realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));

        realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults()
                        .WithLogout(Boolean.TRUE, "https://endpoint?query-param-1=test")
                        .build();
        assertEquals(
                "https://endpoint?query-param-1=test&id_token_hint=my-id-token&post_logout_redirect_uri=https%3A%2F%2Flocalhost",
                realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));
    }

    @Test
    @WithoutJenkins
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
        assertEquals("https://endpoint", realm.maybeOpenIdLogoutEndpoint(null, null, null));
    }

    @Test
    @WithoutJenkins
    public void testMaybeOpenIdLogoutEndpointWithCustomLogoutQueryParameters() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMockRule)
                .WithMinimalDefaults()
                        .WithLogoutQueryParameters(List.of(
                                new OicQueryParameterConfiguration("key1", " with-spaces   "),
                                new OicQueryParameterConfiguration("param-only", ""),
                                new OicQueryParameterConfiguration("id_token_hint", "overwrite-test-1"),
                                new OicQueryParameterConfiguration("post_logout_redirect_uri", "overwrite-test-2"),
                                new OicQueryParameterConfiguration("state", "overwrite-test-3")))
                        .WithLogout(true, "https://endpoint")
                        .build();
        String result = realm.maybeOpenIdLogoutEndpoint("my-id-token", "test", "https://localhost");
        assertNotNull(result);
        assertFalse(result.contains("overwrite-test"));
        assertEquals(
                "https://endpoint?key1=with-spaces&id_token_hint=my-id-token&state=test&post_logout_redirect_uri=https%3A%2F%2Flocalhost&param-only",
                result);
    }
}

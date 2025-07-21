package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasItemInArray;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.util.Secret;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;
import org.htmlunit.Page;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCrypt;

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
    @WithoutJenkins
    public void testMaybeOpenIdLogoutEndpoint() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithLogout(Boolean.FALSE, "https://endpoint")
                        .build();
        Assertions.assertNull(realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));

        realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults().WithLogout(Boolean.TRUE, null).build();
        Assertions.assertNull(realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));

        realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults().WithLogout(Boolean.FALSE, null).build();
        Assertions.assertNull(realm.maybeOpenIdLogoutEndpoint("my-id-token", null, "https://localhost"));

        realm = new TestRealm.Builder(wireMock)
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
        TestRealm realm = new TestRealm.Builder(wireMock)
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
    public void testMaybeOpenIdLogoutEndpointWithCustomLogoutQueryParameters(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule
                .jenkins
                .getDescriptorList(LogoutQueryParameter.class)
                .add(new LogoutQueryParameter.DescriptorImpl());
        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithLogoutQueryParameters(List.of(
                                new LogoutQueryParameter("key1", " with-spaces   "),
                                new LogoutQueryParameter("param-only", "")))
                        .WithLogout(true, "https://endpoint")
                        .build();
        String result = realm.maybeOpenIdLogoutEndpoint("my-id-token", "test", "https://localhost");
        assertNotNull(result);
        assertFalse(result.contains("overwrite-test"));
        assertEquals(
                "https://endpoint?id_token_hint=my-id-token&state=test&post_logout_redirect_uri=https%3A%2F%2Flocalhost&key1=with-spaces&param-only",
                result);
    }

    @Test
    public void testMaybeOpenIdLogoutEndpointWithLogoutQueryParameters(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule
                .jenkins
                .getDescriptorList(LogoutQueryParameter.class)
                .add(new LogoutQueryParameter.DescriptorImpl());
        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithLogoutQueryParameters(List.of(
                                new LogoutQueryParameter("a/test#", "1"),
                                new LogoutQueryParameter("b", ","),
                                new LogoutQueryParameter("b+", "$other:new"),
                                new LogoutQueryParameter("&ampersand", " 2@+ , ?"),
                                new LogoutQueryParameter("d=", " 2 "),
                                new LogoutQueryParameter("iamnull", null),
                                new LogoutQueryParameter(" e? ", "     ")))
                        .WithLogout(true, "https://endpoint")
                        .build();
        String result = realm.maybeOpenIdLogoutEndpoint("my-id-token", "test", "https://localhost");
        assertNotNull(result);
        assertFalse(result.contains("overwrite-test"));
        String queryParams = result.replace("https://endpoint?", "");
        assertEquals(
                Stream.of(
                                "b=%2C",
                                "id_token_hint=my-id-token",
                                "a%2Ftest%23=1",
                                "state=test",
                                "post_logout_redirect_uri=https%3A%2F%2Flocalhost",
                                "d%3D=2",
                                "iamnull",
                                "b%2B=%24other%3Anew",
                                "%26ampersand=2%40%2B+%2C+%3F",
                                "e%3F")
                        .sorted()
                        .toList(),
                Stream.of(queryParams.split("&")).sorted().toList());
    }

    @Test
    public void testOpenIdLoginEndpointWithCustomLoginQueryParameters(JenkinsRule jenkinsRule) throws Exception {
        jenkinsRule
                .jenkins
                .getDescriptorList(LogoutQueryParameter.class)
                .add(new LogoutQueryParameter.DescriptorImpl());
        TestRealm realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithLoginQueryParameters(List.of(
                                new LoginQueryParameter("key1", "value1"),
                                new LoginQueryParameter("key with space", " space "),
                                new LoginQueryParameter("blah:wibble", "anything:here"),
                                new LoginQueryParameter("emailaddr", "joe@example.com")))
                        .build();
        jenkinsRule.jenkins.setSecurityRealm(realm);
        try (WebClient wc = jenkinsRule.createWebClient()) {
            wc.getOptions().setRedirectEnabled(false);
            wc.getOptions().setThrowExceptionOnFailingStatusCode(false);
            Page redirect = wc.goTo("securityRealm/commenceLogin", null);
            String locationHeader = redirect.getWebResponse().getResponseHeaderValue("Location");
            // alas PAC4j does not maintain any ordering of its built URL
            assertThat(locationHeader, startsWith(wireMock.baseUrl()));
            URL u = new URL(locationHeader);
            String[] queries = u.getQuery().split("&");
            assertThat(
                    queries,
                    allOf(
                            hasItemInArray("key1=value1"),
                            hasItemInArray("key%20with%20space=space"),
                            hasItemInArray("blah%3Awibble=anything%3Ahere"),
                            hasItemInArray("emailaddr=joe%40example.com")));
        }
    }
}

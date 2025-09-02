package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import hudson.model.User;
import hudson.security.SecurityRealm;
import java.lang.reflect.Field;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.mockito.MockedStatic;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

@WithJenkins
public class OicSecurityRealmTokenExpirationTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort().dynamicHttpsPort())
            .build();

    private Jenkins jenkins;
    private JenkinsRule.WebClient webClient;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        jenkins = jenkinsRule.getInstance();
        webClient = jenkinsRule.createWebClient();
    }

    @AfterEach
    void tearDown() {
        webClient.close();
    }

    @Test
    void handleTokenExpiration_noUser() throws Exception {
        final TestRealm realm = new TestRealm.Builder(wireMock).build();
        jenkins.setSecurityRealm(realm);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        try (MockedStatic<User> userMocked = mockStatic(User.class)) {
            userMocked.when(() -> User.get2(any())).thenReturn(null);

            User user = User.get2(authentication);
            Assertions.assertNull(user);
            Assertions.assertTrue(realm.handleTokenExpiration(
                    new MockHttpServletRequest() {
                        @Override
                        public String getRequestURI() {
                            return "/other";
                        }
                    },
                    null));
        }
    }

    @Test
    void handleTokenExpiration_AllowTokenAccessWithoutOicSession() throws Exception {
        final TestRealm realm = new TestRealm.Builder(wireMock).build();
        realm.setAllowTokenAccessWithoutOicSession(true);
        jenkins.setSecurityRealm(realm);

        // User mock
        User mockUser = mock(User.class);
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest() {
            @Override
            public String getRequestURI() {
                return "/other";
            }

            @Override
            public String getHeader(String name) {
                // hello:world
                return "Basic aGVsbG86d29ybGQ=";
            }
        };
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Static method User.get2(authentication) mock
        try (MockedStatic<User> mockedUser = mockStatic(User.class)) {
            mockedUser.when((MockedStatic.Verification) User.get2(any())).thenReturn(mockUser);

            Assertions.assertFalse(realm.isLogoutRequest(mockHttpServletRequest));
            User user = User.get2(authentication);
            Assertions.assertNotNull(user);
            Assertions.assertNull(user.getProperty(OicCredentials.class));
            Assertions.assertTrue(realm.isAllowTokenAccessWithoutOicSession());

            // ------------- W/O AUTH HEADER
            Assertions.assertFalse(realm.isValidApiTokenRequest(
                    new MockHttpServletRequest() {
                        @Override
                        public String getRequestURI() {
                            return "/other";
                        }

                        @Override
                        public String getHeader(String name) {
                            return "Authorization".equals(name) ? null : "Testheader";
                        }
                    },
                    user));

            // ------------- W/O BASIC AUTH HEADER
            Assertions.assertFalse(realm.isValidApiTokenRequest(
                    new MockHttpServletRequest() {
                        @Override
                        public String getRequestURI() {
                            return "/other";
                        }

                        @Override
                        public String getHeader(String name) {
                            return "Other";
                        }
                    },
                    user));

            // ------------- W/O API TOKEN
            Assertions.assertFalse(realm.isValidApiTokenRequest(mockHttpServletRequest, user));

            // ------------- WITH API TOKEN
            ApiTokenProperty mockApiTokenProperty = mock(ApiTokenProperty.class);
            when(mockUser.getProperty(ApiTokenProperty.class)).thenReturn(mockApiTokenProperty);

            // ........ WITH INVALID API TOKEN
            Assertions.assertFalse(realm.isValidApiTokenRequest(mockHttpServletRequest, user));
            when(mockApiTokenProperty.matchesPassword(any())).thenReturn(false);

            // ........ WITH API TOKEN
            when(mockApiTokenProperty.matchesPassword(any())).thenReturn(true);
            Assertions.assertTrue(realm.isValidApiTokenRequest(mockHttpServletRequest, user));
            Assertions.assertTrue(realm.handleTokenExpiration(mockHttpServletRequest, null));
        }
    }

    @Test
    void handleTokenExpiration_logoutRequestUri() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        MockHttpServletRequest request = new MockHttpServletRequest() {
            @Override
            public String getRequestURI() {
                return "/logout";
            }
        };
        MockHttpServletResponse response = new MockHttpServletResponse();

        Assertions.assertTrue(realm.isLogoutRequest(request));
        Assertions.assertTrue(realm.handleTokenExpiration(request, response));
    }

    @Test
    void handleTokenExpiration_noAuthenticationOrAnonymous() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        SecurityContextHolder.getContext().setAuthentication(null);
        Assertions.assertFalse(realm.isLogoutRequest(request));
        Assertions.assertTrue(realm.handleTokenExpiration(request, response));

        String key = "testKey";
        Object principal = "testUser";

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        org.springframework.security.authentication.AnonymousAuthenticationToken token =
                new org.springframework.security.authentication.AnonymousAuthenticationToken(
                        key, principal, grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(token);

        Assertions.assertFalse(realm.isLogoutRequest(request));
        Assertions.assertTrue(realm.handleTokenExpiration(request, response));
    }

    @Test
    void handleTokenExpiration_NoOicCredentials() throws Exception {
        final TestRealm realm = new TestRealm.Builder(wireMock).build();
        jenkins.setSecurityRealm(realm);

        MockHttpServletRequest request = new MockHttpServletRequest() {
            @Override
            public String getRequestURI() {
                return "/other";
            }
        };
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // User mock
        User mockUser = mock(User.class);
        when(mockUser.getProperty(OicCredentials.class)).thenReturn(null);

        // Static method User.get2(authentication) mock
        try (MockedStatic<User> mockedUser = mockStatic(User.class)) {
            mockedUser.when((MockedStatic.Verification) User.get2(any())).thenReturn(mockUser);

            Assertions.assertFalse(realm.isLogoutRequest(request));
            User user = User.get2(authentication);
            Assertions.assertNotNull(user);
            Assertions.assertNull(user.getProperty(OicCredentials.class));
            Assertions.assertTrue(realm.handleTokenExpiration(request, response));
        }
    }

    @Test
    void handleTokenExpiration() throws Exception {
        final TestRealm realm = new TestRealm.Builder(wireMock).build();
        realm.setTokenExpirationCheckDisabled(true);
        jenkins.setSecurityRealm(realm);

        MockHttpServletRequest request = new MockHttpServletRequest() {
            @Override
            public String getRequestURI() {
                return "/other";
            }
        };
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // User mock
        User mockUser = mock(User.class);
        OicCredentials mockOicCredentials = mock(OicCredentials.class);
        when(mockUser.getProperty(OicCredentials.class)).thenReturn(mockOicCredentials);
        when(mockOicCredentials.getExpiresAtMillis()).thenReturn(null);

        // Static method User.get2(authentication) mock
        try (MockedStatic<User> mockedUser = mockStatic(User.class)) {
            mockedUser.when((MockedStatic.Verification) User.get2(any())).thenReturn(mockUser);

            Assertions.assertFalse(realm.isLogoutRequest(request));
            User user = User.get2(authentication);
            Assertions.assertNotNull(user);
            Assertions.assertNotNull(user.getProperty(OicCredentials.class));
            Assertions.assertFalse(realm.isAllowTokenAccessWithoutOicSession());

            // ------------ NOT EXPIRED
            Assertions.assertFalse(realm.isExpired(mockOicCredentials));
            Assertions.assertTrue(realm.handleTokenExpiration(request, null));

            // ------------ EXPIRED
            when(mockOicCredentials.getExpiresAtMillis())
                    .thenReturn(Clock.systemUTC().millis() - 10);
            Assertions.assertTrue(realm.isExpired(mockOicCredentials));

            // ...... W/O REFRESH - Token Expiration Check is DISABLED
            Assertions.assertFalse(realm.canRefreshToken(mockOicCredentials));
            Assertions.assertTrue(realm.isTokenExpirationCheckDisabled());
            Assertions.assertTrue(realm.handleTokenExpiration(request, null));

            // ...... WITH REFRESH - Token Expiration Check is ENABLED
            realm.setTokenExpirationCheckDisabled(false);

            TestRealm spyRealm = spy(realm);
            Assertions.assertFalse(spyRealm.canRefreshToken(mockOicCredentials));
            Assertions.assertFalse(spyRealm.isTokenExpirationCheckDisabled());
            doNothing().when(spyRealm).redirectToLoginUrl(any(), any());
            Assertions.assertFalse(spyRealm.handleTokenExpiration(request, null));

            // ...... can refresh
            OicServerConfiguration mockOicServerConfiguration = mock(OicServerConfiguration.class);
            Field privateField = OicSecurityRealm.class.getDeclaredField("serverConfiguration");
            privateField.setAccessible(true);
            privateField.set(spyRealm, mockOicServerConfiguration);
            OIDCProviderMetadata mockOIDCProviderMetadata = mock(OIDCProviderMetadata.class);
            when(mockOicServerConfiguration.toProviderMetadata()).thenReturn(mockOIDCProviderMetadata);

            when(mockOIDCProviderMetadata.getGrantTypes()).thenReturn(List.of(GrantType.AUTHORIZATION_CODE));
            Assertions.assertFalse(spyRealm.canRefreshToken(mockOicCredentials));

            when(mockOIDCProviderMetadata.getGrantTypes()).thenReturn(List.of(GrantType.REFRESH_TOKEN));
            Assertions.assertFalse(spyRealm.canRefreshToken(mockOicCredentials));
            when(mockOicCredentials.getRefreshToken()).thenReturn("refreshToken");
            Assertions.assertTrue(spyRealm.canRefreshToken(mockOicCredentials));

            // ...... expired token has been refreshed
            doReturn(true).when(spyRealm).refreshExpiredToken(any(), any(), any(), any());
            Assertions.assertTrue(spyRealm.handleTokenExpiration(request, null));

            // ...... expired token has NOT been refreshed
            doReturn(false).when(spyRealm).refreshExpiredToken(any(), any(), any(), any());
            Assertions.assertFalse(spyRealm.handleTokenExpiration(request, null));
        }
    }
}

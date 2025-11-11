package org.jenkinsci.plugins.oic;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import hudson.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.util.List;
import jenkins.security.ApiTokenProperty;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class OicSecurityRealmTokenExpirationTest {

    @Test
    void handleTokenExpiration_logoutRequestUri() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.isLogoutRequest(any())).thenCallRealMethod();
        when(realm.handleTokenExpiration(any(), any())).thenCallRealMethod();

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/logout");

        assertTrue(realm.isLogoutRequest(request));
        assertTrue(realm.handleTokenExpiration(request, null));
    }

    @Test
    void handleTokenExpiration_noUser() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.isLogoutRequest(any())).thenCallRealMethod();
        when(realm.handleTokenExpiration(any(), any())).thenCallRealMethod();

        try (MockedStatic<User> userMocked = mockStatic(User.class)) {
            userMocked.when(() -> User.get2(any())).thenReturn(null);

            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("/other");

            assertFalse(realm.isLogoutRequest(request));
            assertTrue(realm.handleTokenExpiration(request, null));
        }
    }

    @Test
    void handleTokenExpiration_NoOicCredentials() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.isLogoutRequest(any())).thenCallRealMethod();
        when(realm.handleTokenExpiration(any(), any())).thenCallRealMethod();

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/other");
        HttpServletResponse response = mock(HttpServletResponse.class);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // User mock
        User mockUser = mock(User.class);
        when(mockUser.getProperty(OicCredentials.class)).thenReturn(null);

        // Static method User.get2(authentication) mock
        try (MockedStatic<User> mockedUser = mockStatic(User.class)) {
            mockedUser.when((MockedStatic.Verification) User.get2(any())).thenReturn(mockUser);
            // no logout request
            assertFalse(realm.isLogoutRequest(request));

            // user not null
            User user = User.get2(authentication);
            Assertions.assertNotNull(user);

            // OicCredentials is null
            Assertions.assertNull(user.getProperty(OicCredentials.class));
            assertTrue(realm.handleTokenExpiration(request, response));
        }
    }

    @Test
    void handleTokenExpiration_isValidApiTokenRequest_AllowTokenAccessWithoutOicSession() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        ApiTokenProperty mockApiTokenProperty = mock(ApiTokenProperty.class);
        User mockUser = mock(User.class);

        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.isValidApiTokenRequest(any(), any())).thenCallRealMethod();

        // ---- Token access w/o OIC Session not allowed
        assertFalse(realm.isValidApiTokenRequest(null, null));

        // ---- Allow token access with OIC Session
        when(realm.isAllowTokenAccessWithoutOicSession()).thenReturn(true);

        // ---- No basic auth header set
        when(request.getHeader(any())).thenReturn(null);
        assertFalse(realm.isValidApiTokenRequest(request, null));
        when(request.getHeader(any())).thenReturn("Other value");
        assertFalse(realm.isValidApiTokenRequest(request, null));

        // ---- Basic auth header set: hello:world but no ApiTokenProperty
        when(request.getHeader(any())).thenReturn("Basic aGVsbG86d29ybGQ=");
        when(mockUser.getProperty(ApiTokenProperty.class)).thenReturn(null);
        assertFalse(realm.isValidApiTokenRequest(request, mockUser));

        // ---- Basic auth header set: hello:world AND ApiTokenProperty but passwords do not match
        when(mockUser.getProperty(ApiTokenProperty.class)).thenReturn(mockApiTokenProperty);
        when(mockApiTokenProperty.matchesPassword(any())).thenReturn(false);
        assertFalse(realm.isValidApiTokenRequest(request, mockUser));

        // ---- Basic auth header set: hello:world AND ApiTokenProperty AND passwords match
        when(mockUser.getProperty(ApiTokenProperty.class)).thenReturn(mockApiTokenProperty);
        when(mockApiTokenProperty.matchesPassword(any())).thenReturn(true);
        assertTrue(realm.isValidApiTokenRequest(request, mockUser));
    }

    @Test
    void handleTokenExpiration_isExpired_and_canRefresh() throws Exception {
        User mockUser = mock(User.class);
        OicCredentials mockOicCredentials = mock(OicCredentials.class);
        OicServerConfiguration mockOicServerConfiguration = mock(OicServerConfiguration.class);
        OIDCProviderMetadata mockOIDCProviderMetadata = mock(OIDCProviderMetadata.class);

        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(true);
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenCallRealMethod();
        when(mockOicServerConfiguration.toProviderMetadata()).thenReturn(mockOIDCProviderMetadata);
        when(realm.getServerConfiguration()).thenReturn(mockOicServerConfiguration);

        when(mockUser.getProperty(OicCredentials.class)).thenReturn(mockOicCredentials);
        when(mockOicCredentials.getExpiresAtMillis()).thenReturn(null);
        assertFalse(realm.isExpired(mockOicCredentials));

        // ------------ EXPIRED
        when(mockOicCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        assertTrue(realm.isExpired(mockOicCredentials));

        // ------------ NOT EXPIRED
        when(mockOicCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() + 10);
        assertFalse(realm.isExpired(mockOicCredentials));

        // ------------ CAN REFRESH
        when(mockOIDCProviderMetadata.getGrantTypes()).thenReturn(List.of(GrantType.AUTHORIZATION_CODE));
        assertFalse(realm.canRefreshToken(mockOicCredentials));

        when(mockOIDCProviderMetadata.getGrantTypes()).thenReturn(List.of(GrantType.REFRESH_TOKEN));
        assertFalse(realm.canRefreshToken(mockOicCredentials));

        when(mockOicCredentials.getRefreshToken()).thenReturn("refreshToken");
        assertTrue(realm.canRefreshToken(mockOicCredentials));
    }
}

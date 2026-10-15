package org.jenkinsci.plugins.oic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import hudson.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import jenkins.security.ApiTokenProperty;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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
    void handleTokenExpiration_isValidApiTokenRequest_AllowTokenAccessWithoutOicSession() {
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
    void handleTokenExpiration_isExpired_and_canRefresh() {
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

        when(mockOIDCProviderMetadata.getGrantTypes()).thenReturn(null);
        assertTrue(realm.canRefreshToken(mockOicCredentials));
    }

    @Test
    void handleExpiredToken_concurrentRefreshOnlyRefreshesOnce() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(true);

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        OicCredentials refreshedCredentials = mock(OicCredentials.class);
        when(refreshedCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() + 60_000);

        User user = mock(User.class);
        when(user.getId()).thenReturn("concurrent-refresh-user");

        AtomicBoolean refreshed = new AtomicBoolean(false);
        when(user.getProperty(OicCredentials.class))
                .thenAnswer(invocation -> refreshed.get() ? refreshedCredentials : expiredCredentials);

        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch releaseRefresh = new CountDownLatch(1);
        AtomicInteger refreshCount = new AtomicInteger();
        when(realm.refreshExpiredToken(anyString(), any(), any(), any())).thenAnswer(invocation -> {
            refreshCount.incrementAndGet();
            refreshStarted.countDown();
            assertTrue(releaseRefresh.await(5, TimeUnit.SECONDS));
            refreshed.set(true);
            return true;
        });

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = executor.submit(() -> realm.handleExpiredToken(user, request, response));
            assertTrue(refreshStarted.await(5, TimeUnit.SECONDS));

            Future<Boolean> second = executor.submit(() -> realm.handleExpiredToken(user, request, response));
            TimeUnit.MILLISECONDS.sleep(100);

            releaseRefresh.countDown();

            assertTrue(first.get(5, TimeUnit.SECONDS));
            assertTrue(second.get(5, TimeUnit.SECONDS));
        } finally {
            releaseRefresh.countDown();
            executor.shutdownNow();
        }

        assertEquals(1, refreshCount.get());
        verify(realm, times(1)).refreshExpiredToken(anyString(), any(), any(), any());
    }

    @Test
    void handleTokenExpiration_expiredCredentialsDelegateToLockedRefreshPath() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.isLogoutRequest(any())).thenCallRealMethod();
        when(realm.handleTokenExpiration(any(), any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        User user = mock(User.class);
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/job/example/");
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(realm.handleExpiredToken(user, request, response)).thenReturn(false);

        try (MockedStatic<User> userMocked = mockStatic(User.class)) {
            userMocked.when(() -> User.get2(any())).thenReturn(user);

            assertFalse(realm.handleTokenExpiration(request, response));
        }

        verify(realm).handleExpiredToken(user, request, response);
    }

    @Test
    void handleExpiredToken_returnsWhenCredentialsDisappearOrAreAlreadyFresh() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();

        User user = mock(User.class);
        when(user.getId()).thenReturn("fresh-after-lock-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(null);
        assertTrue(realm.handleExpiredToken(user, null, null));

        OicCredentials freshCredentials = mock(OicCredentials.class);
        when(freshCredentials.getExpiresAtMillis()).thenReturn(Clock.systemUTC().millis() + 60_000);
        when(user.getProperty(OicCredentials.class)).thenReturn(freshCredentials);
        assertTrue(realm.handleExpiredToken(user, null, null));

        verify(realm, never()).refreshExpiredToken(anyString(), any(), any(), any());
    }

    @Test
    void handleExpiredToken_allowsExpiredTokenWhenExpirationCheckDisabled() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(false);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(true);

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        User user = mock(User.class);
        when(user.getId()).thenReturn("disabled-expiration-check-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        assertTrue(realm.handleExpiredToken(user, null, null));
    }

    @Test
    void handleExpiredToken_redirectsToRootRelativeLoginUrl() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isNonInteractiveRequest(any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(false);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(false);
        when(realm.getLoginUrl()).thenCallRealMethod();

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);

        User user = mock(User.class);
        when(user.getId()).thenReturn("redirect-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        HttpSession session = mock(HttpSession.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(session);
        when(request.getSession()).thenReturn(session);
        when(request.getContextPath()).thenReturn("");
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertFalse(realm.handleExpiredToken(user, request, response));

        verify(session).invalidate();
        verify(response).sendRedirect("/securityRealm/commenceLogin");
    }

    @Test
    void handleExpiredToken_preservesContextPathForRootRelativeLoginUrl() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isNonInteractiveRequest(any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(false);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(false);
        when(realm.getLoginUrl()).thenReturn("/securityRealm/commenceLogin");

        OicServerConfiguration serverConfiguration = mock(OicServerConfiguration.class);
        when(serverConfiguration.toProviderMetadata()).thenThrow(new IllegalStateException("metadata unavailable"));
        when(realm.getServerConfiguration()).thenReturn(serverConfiguration);

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        User user = mock(User.class);
        when(user.getId()).thenReturn("context-path-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        HttpSession session = mock(HttpSession.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(session);
        when(request.getSession()).thenReturn(session);
        when(request.getContextPath()).thenReturn("/jenkins");
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertFalse(realm.handleExpiredToken(user, request, response));

        verify(session).invalidate();
        verify(response).sendRedirect("/jenkins/securityRealm/commenceLogin");
    }

    @Test
    void handleExpiredToken_redirectsWhenRequestIsNull() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isNonInteractiveRequest(any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(false);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(false);
        when(realm.getLoginUrl()).thenReturn("securityRealm/commenceLogin");

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        User user = mock(User.class);
        when(user.getId()).thenReturn("null-request-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        HttpServletResponse response = mock(HttpServletResponse.class);

        assertFalse(realm.handleExpiredToken(user, null, response));

        verify(response).sendRedirect("/securityRealm/commenceLogin");
    }

    @Test
    void handleExpiredToken_withoutExistingSessionInvalidatesCreatedSession() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isNonInteractiveRequest(any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(false);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(false);
        when(realm.getLoginUrl()).thenReturn("/securityRealm/commenceLogin");

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        when(expiredCredentials.getRefreshToken()).thenReturn("refresh-token");
        User user = mock(User.class);
        when(user.getId()).thenReturn("new-session-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        HttpSession session = mock(HttpSession.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(null);
        when(request.getSession()).thenReturn(session);
        when(request.getContextPath()).thenReturn("");
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertFalse(realm.handleExpiredToken(user, request, response));

        verify(session).invalidate();
        verify(response).sendRedirect("/securityRealm/commenceLogin");
    }

    @Test
    void handleExpiredToken_withAuthorizationHeaderDoesNotInvalidateSession() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isNonInteractiveRequest(any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(false);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(false);
        when(realm.getLoginUrl()).thenReturn("/securityRealm/commenceLogin");

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);
        User user = mock(User.class);
        when(user.getId()).thenReturn("authorization-header-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        HttpSession session = mock(HttpSession.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(null);
        when(request.getSession()).thenReturn(session);
        when(request.getHeader("Authorization")).thenReturn("Bearer token");
        when(request.getContextPath()).thenReturn("");
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertFalse(realm.handleExpiredToken(user, request, response));

        verify(session, never()).invalidate();
        verify(response).sendRedirect("/securityRealm/commenceLogin");
    }

    @Test
    void handleExpiredToken_nonInteractiveRequestReturnsUnauthorizedInsteadOfRedirect() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.handleExpiredToken(any(), any(), any())).thenCallRealMethod();
        when(realm.isNonInteractiveRequest(any())).thenCallRealMethod();
        when(realm.isExpired(any())).thenCallRealMethod();
        when(realm.canRefreshToken(any())).thenReturn(false);
        when(realm.isTokenExpirationCheckDisabled()).thenReturn(false);

        OicCredentials expiredCredentials = mock(OicCredentials.class);
        when(expiredCredentials.getExpiresAtMillis())
                .thenReturn(Clock.systemUTC().millis() - 10);

        User user = mock(User.class);
        when(user.getId()).thenReturn("ajax-user");
        when(user.getProperty(OicCredentials.class)).thenReturn(expiredCredentials);

        HttpSession session = mock(HttpSession.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getSession(false)).thenReturn(session);
        when(request.getRequestURI()).thenReturn("/widget/BuildQueueWidget/ajax");
        when(request.getHeader("Sec-Fetch-Dest")).thenReturn("empty");
        when(request.getHeader("Accept")).thenReturn("*/*");
        when(request.getHeader("Jenkins-Crumb")).thenReturn("crumb");
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertFalse(realm.handleExpiredToken(user, request, response));

        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response, never()).sendRedirect(anyString());
        verify(session, never()).invalidate();
    }

    @Test
    void isNonInteractiveRequest_recognizesEachSupportedRequestSignal() {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        when(realm.isNonInteractiveRequest(any())).thenCallRealMethod();

        assertFalse(realm.isNonInteractiveRequest(null));

        HttpServletRequest xhr = mock(HttpServletRequest.class);
        when(xhr.getHeader("X-Requested-With")).thenReturn("xmlhttprequest");
        assertTrue(realm.isNonInteractiveRequest(xhr));

        HttpServletRequest fetch = mock(HttpServletRequest.class);
        when(fetch.getHeader("Sec-Fetch-Dest")).thenReturn("empty");
        assertTrue(realm.isNonInteractiveRequest(fetch));

        HttpServletRequest api = mock(HttpServletRequest.class);
        when(api.getHeader("Accept")).thenReturn("application/json");
        assertTrue(realm.isNonInteractiveRequest(api));

        HttpServletRequest ajaxPath = mock(HttpServletRequest.class);
        when(ajaxPath.getRequestURI()).thenReturn("/widget/ExecutorWidget/ajax");
        assertTrue(realm.isNonInteractiveRequest(ajaxPath));

        HttpServletRequest crumb = mock(HttpServletRequest.class);
        when(crumb.getHeader("Jenkins-Crumb")).thenReturn("crumb");
        assertTrue(realm.isNonInteractiveRequest(crumb));

        HttpServletRequest navigation = mock(HttpServletRequest.class);
        when(navigation.getHeader("Sec-Fetch-Dest")).thenReturn("document");
        when(navigation.getHeader("Accept")).thenReturn("text/html,application/xhtml+xml");
        when(navigation.getRequestURI()).thenReturn("/job/example/");
        assertFalse(realm.isNonInteractiveRequest(navigation));

        HttpServletRequest iframe = mock(HttpServletRequest.class);
        when(iframe.getHeader("Sec-Fetch-Dest")).thenReturn("iframe");
        assertFalse(realm.isNonInteractiveRequest(iframe));

        HttpServletRequest xhtml = mock(HttpServletRequest.class);
        when(xhtml.getHeader("Accept")).thenReturn("application/xhtml+xml");
        assertFalse(realm.isNonInteractiveRequest(xhtml));
    }

    @Test
    void expireCredentials_replacesCredentialsWithExpiredEmptyTokens() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        doCallRealMethod().when(realm).expireCredentials(anyString());

        User user = mock(User.class);
        try (MockedStatic<User> userMocked = mockStatic(User.class)) {
            userMocked.when(() -> User.getById("expired-user", false)).thenReturn(user);

            realm.expireCredentials("expired-user");
        }

        ArgumentCaptor<OicCredentials> credentials = ArgumentCaptor.forClass(OicCredentials.class);
        verify(user).addProperty(credentials.capture());

        OicCredentials expiredCredentials = credentials.getValue();
        assertFalse(expiredCredentials.getAccessToken() != null
                && !expiredCredentials.getAccessToken().isEmpty());
        assertFalse(expiredCredentials.getIdToken() != null
                && !expiredCredentials.getIdToken().isEmpty());
        assertFalse(expiredCredentials.getRefreshToken() != null
                && !expiredCredentials.getRefreshToken().isEmpty());
        assertTrue(expiredCredentials.getExpiresAtMillis() <= Clock.systemUTC().millis());
    }

    @Test
    void expireCredentials_ignoresMissingUser() throws Exception {
        OicSecurityRealm realm = mock(OicSecurityRealm.class);
        doCallRealMethod().when(realm).expireCredentials(anyString());

        try (MockedStatic<User> userMocked = mockStatic(User.class)) {
            userMocked.when(() -> User.getById("missing-user", false)).thenReturn(null);

            realm.expireCredentials("missing-user");
        }
    }
}

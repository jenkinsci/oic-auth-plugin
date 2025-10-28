package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.User;
import jenkins.security.ApiTokenProperty;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class OicSecurityRealmPlainTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort())
            .build();

    @Test
    public void testIsValidApiTokenRequest_NoTokenAccessWithoutOicSession() throws Exception {
        TestRealm realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();
        assertFalse(realm.isAllowTokenAccessWithoutOicSession());

        MockHttpServletRequest request = new MockHttpServletRequest();
        User mockUser = mock(User.class);
        assertFalse(realm.isValidApiTokenRequest(request, mockUser));
    }

    @Test
    public void testIsValidApiTokenRequest_WithTokenAccessWithoutOicSession() throws Exception {
        final TestRealm realm = new TestRealm.Builder(wireMock).build();
        realm.setAllowTokenAccessWithoutOicSession(true);

        MockHttpServletRequest request = new MockHttpServletRequest() {
            @Override
            public String getHeader(String name) {
                // hello:world
                return "Basic aGVsbG86d29ybGQ=";
            }
        };

        User mockUser = mock(User.class);
        ApiTokenProperty mockApiTokenProperty = mock(ApiTokenProperty.class);
        assertNotNull(mockUser);
        when(mockUser.getProperty(ApiTokenProperty.class)).thenReturn(mockApiTokenProperty);
        when(mockApiTokenProperty.matchesPassword(any())).thenReturn(true);
        assertTrue(realm.isValidApiTokenRequest(request, mockUser));
    }
}

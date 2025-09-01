package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.model.User;
import java.time.Clock;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.mockito.MockedStatic;

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

        try (MockedStatic<User> userMocked = mockStatic(User.class)) {
            userMocked.when(() -> User.get2(any())).thenReturn(null);
            assertTrue(realm.handleTokenExpiration(
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

        // ------------- W/o ApiTokenProperty
        try (MockedStatic<User> mockedUser = mockStatic(User.class)) {
            mockedUser.when(() -> User.get2(any())).thenReturn(mockUser);

            assertTrue(realm.handleTokenExpiration(mockHttpServletRequest, null));
        }

        // ------------- With ApiTokenProperty
        ApiTokenProperty mockApiTokenProperty = mock(ApiTokenProperty.class);
        when(mockUser.getProperty(ApiTokenProperty.class)).thenReturn(mockApiTokenProperty);

        // Static method User.get2(authentication) mock
        try (MockedStatic<User> mockedUser = mockStatic(User.class)) {
            mockedUser.when(() -> User.get2(any())).thenReturn(mockUser);

            when(mockApiTokenProperty.matchesPassword(any())).thenReturn(true);
            assertTrue(realm.handleTokenExpiration(mockHttpServletRequest, null));

            OicCredentials mockOicCredentials = mock(OicCredentials.class);
            when(mockUser.getProperty(OicCredentials.class)).thenReturn(mockOicCredentials);
            when(mockApiTokenProperty.matchesPassword(any())).thenReturn(false);
            when(mockOicCredentials.getExpiresAtMillis())
                    .thenReturn(Clock.systemUTC().millis() + 10);
            assertFalse(realm.isExpired(mockOicCredentials));
            assertTrue(realm.handleTokenExpiration(mockHttpServletRequest, null));
        }
    }
}

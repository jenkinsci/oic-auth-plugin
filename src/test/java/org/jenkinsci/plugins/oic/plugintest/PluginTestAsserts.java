package org.jenkinsci.plugins.oic.plugintest;

import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_EMAIL_ADDRESS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_FULL_NAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_GROUPS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.tasks.UserAvatarResolver;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.avatar.AvatarProperty;
import org.junit.jupiter.api.Assertions;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.Authentication;

public class PluginTestAsserts {

    /** The value {@link UserAvatarResolver} falls back to when nothing can resolve an avatar. */
    public static final String DEFAULT_AVATAR = "symbol-person-circle";

    public static void assertAnonymous(@NonNull JenkinsRule.WebClient webClient) {
        Assertions.assertEquals(
                Jenkins.ANONYMOUS2.getPrincipal(),
                PluginTestHelper.getAuthentication(webClient).getPrincipal(),
                "Shouldn't be authenticated");
    }

    public static void assertTestUserIsMemberOfTestGroups(User user) {
        assertTestUserIsMemberOfGroups(user, TEST_USER_GROUPS);
    }

    public static @NonNull User assertTestUser(@NonNull JenkinsRule.WebClient webClient) {
        Authentication authentication = PluginTestHelper.getAuthentication(webClient);
        assertEquals(TEST_USER_USERNAME, authentication.getPrincipal(), "Should be logged-in as " + TEST_USER_USERNAME);
        User user = PluginTestHelper.toUser(authentication);
        assertNotNull(user);
        assertEquals(TEST_USER_FULL_NAME, user.getFullName(), "Full name should be " + TEST_USER_FULL_NAME);
        return user;
    }

    public static void assertTestUserEmail(User user) {
        assertEquals(
                TEST_USER_EMAIL_ADDRESS,
                user.getProperty(Mailer.UserProperty.class).getAddress(),
                "Email should be " + TEST_USER_EMAIL_ADDRESS);
    }

    /**
     * Asserts the avatar of the user is the raw URL advertised by the provider, i.e. the behaviour of
     * {@code ServeFromURLAvatarHandler} (the default).
     * <p>
     * A {@code null} user asserts the generic fallback instead.
     */
    public static void assertTestAvatar(User user, WireMockExtension wireMock) {
        assertTestAvatar(user, user == null ? null : wireMock.url("/my-avatar.png"));
    }

    /**
     * As {@link #assertTestAvatar(User, WireMockExtension)} but with an explicit expected URL, for tests where the
     * avatar is not at {@link WireMockExtension#url(String)} (which prefers {@code https} once an https port is
     * enabled).
     */
    public static void assertTestAvatar(User user, String expectedAvatarUrl) {
        if (user != null) {
            AvatarProperty avatarProperty = user.getProperty(AvatarProperty.class);
            assertNotNull(avatarProperty, "User should have an " + AvatarProperty.class.getSimpleName());
            assertEquals(expectedAvatarUrl, avatarProperty.getAvatarUrl(), "Avatar url should be " + expectedAvatarUrl);
            String urlViaAvatarResolver = UserAvatarResolver.resolve(user, "48x48");
            assertEquals(expectedAvatarUrl, urlViaAvatarResolver, "Avatar url should be " + expectedAvatarUrl);
        } else {
            String urlViaAvatarResolver = UserAvatarResolver.resolve(null, "48x48");
            assertEquals(DEFAULT_AVATAR, urlViaAvatarResolver, "Avatar url should be " + DEFAULT_AVATAR);
        }
    }

    /**
     * Asserts that the user has no avatar at all: either no {@code AvatarProperty}, or one that
     * yields no URL. Also asserts nothing is cached on disk.
     */
    public static void assertNoAvatar(@NonNull User user) {
        AvatarProperty avatarProperty = user.getProperty(AvatarProperty.class);
        if (avatarProperty != null) {
            assertNull(
                    avatarProperty.getAvatarUrl(),
                    "User " + user.getId() + " should not have an avatar url, but had "
                            + avatarProperty.getAvatarUrl());
        }
        assertEquals(
                DEFAULT_AVATAR,
                UserAvatarResolver.resolve(user, "48x48"),
                "Avatar url should be the " + DEFAULT_AVATAR + " fallback");
    }

    public static void assertTestUserIsMemberOfGroups(User user, String... testUserGroups) {
        for (String group : testUserGroups) {
            assertTrue(user.getAuthorities().contains(group), "User should be part of group " + group);
        }
    }
}

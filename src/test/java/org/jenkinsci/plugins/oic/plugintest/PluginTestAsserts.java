package org.jenkinsci.plugins.oic.plugintest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyArray;
import static org.hamcrest.Matchers.matchesPattern;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_EMAIL_ADDRESS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_FULL_NAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_GROUPS;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.User;
import hudson.tasks.Mailer;
import hudson.tasks.UserAvatarResolver;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.avatar.AvatarProperty;
import org.junit.jupiter.api.Assertions;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.Authentication;

public class PluginTestAsserts {

    /** The value {@link UserAvatarResolver} falls back to when nothing can resolve an avatar. */
    public static final String DEFAULT_AVATAR = "symbol-person-circle";

    /** Prefix of the file name used by {@code AvatarProperty} to cache an image in the user folder. */
    public static final String CACHED_AVATAR_FILE_PREFIX = "oic-avatar.";

    public static void assertAnonymous(@NonNull JenkinsRule.WebClient webClient) {
        Assertions.assertEquals(
                Jenkins.ANONYMOUS2.getPrincipal(),
                PluginTestHelper.getAuthentication(webClient).getPrincipal(),
                "Shouldn't be authenticated");
    }

    public static void assertTestUserIsMemberOfTestGroups(User user) {
        assertTestUserIsMemberOfGroups(user, TEST_USER_GROUPS);
    }

    public static void assertTestUserIsMemberOfGroups(User user, String... testUserGroups) {
        for (String group : testUserGroups) {
            assertTrue(user.getAuthorities().contains(group), "User should be part of group " + group);
        }
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
            assertEquals("OpenID Connect Avatar", avatarProperty.getDisplayName());
            assertNull(avatarProperty.getIconFileName(), "Icon filename must be null");
            String urlViaAvatarResolver = UserAvatarResolver.resolve(user, "48x48");
            assertEquals(expectedAvatarUrl, urlViaAvatarResolver, "Avatar url should be " + expectedAvatarUrl);
            // nothing is cached locally when the browser fetches straight from the provider
            assertNoCachedAvatarFile(user);
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
        assertNoCachedAvatarFile(user);
    }

    /**
     * Asserts that no {@code oic-avatar.*} file is present in the user folder.
     */
    public static void assertNoCachedAvatarFile(@NonNull User user) {
        assertThat("no cached avatar file should exist for " + user.getId(), cachedAvatarFiles(user), emptyArray());
        AvatarProperty avatarProperty = user.getProperty(AvatarProperty.class);
        if (avatarProperty != null) {
            File imageFile = avatarProperty.getImageFile();
            assertTrue(
                    imageFile == null || !imageFile.exists(),
                    "There should be no cached image file, but found " + imageFile);
        }
    }

    /**
     * Asserts that Jenkins has cached the avatar itself and serves it from its own URL space.
     *
     * @return the (absolute) URL the avatar is served from.
     */
    public static @NonNull String assertCachedAvatar(@NonNull User user, byte[] expectedBytes) throws IOException {
        AvatarProperty avatarProperty = user.getProperty(AvatarProperty.class);
        assertNotNull(avatarProperty, "User should have an " + AvatarProperty.class.getSimpleName());

        File imageFile = avatarProperty.getImageFile();
        assertNotNull(imageFile, "the image should have been cached on disk");
        assertTrue(imageFile.isFile(), imageFile + " should exist");
        assertThat(imageFile.getName(), matchesPattern("oic-avatar\\.(png|jpe?g|gif)"));
        assertArrayEquals(expectedBytes, Files.readAllBytes(imageFile.toPath()), "cached bytes should match");

        // exactly one cached file, no leftovers from a previous mode / extension
        assertEquals(1, cachedAvatarFiles(user).length, "there should be exactly one cached avatar file");

        String avatarUrl = avatarProperty.getAvatarUrl();
        assertNotNull(avatarUrl, "the avatar url should not be null");
        String urlViaAvatarResolver = UserAvatarResolver.resolve(user, "48x48");
        assertEquals(avatarUrl, urlViaAvatarResolver, "the resolver should return the property url");
        assertThat(urlViaAvatarResolver, containsString("/user/"));
        assertThat(urlViaAvatarResolver, containsString("/oic-avatar/image"));
        return urlViaAvatarResolver;
    }

    private static File[] cachedAvatarFiles(@NonNull User user) {
        File userFolder = user.getUserFolder();
        if (userFolder == null) {
            return new File[0];
        }
        File[] found = userFolder.listFiles((dir, name) -> name.startsWith(CACHED_AVATAR_FILE_PREFIX));
        return found == null ? new File[0] : found;
    }
}

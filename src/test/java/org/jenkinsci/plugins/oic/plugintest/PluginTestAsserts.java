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
import org.jenkinsci.plugins.oic.OicAvatarProperty;
import org.junit.jupiter.api.Assertions;
import org.jvnet.hudson.test.JenkinsRule;
import org.springframework.security.core.Authentication;

public class PluginTestAsserts {

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

    public static void assertTestAvatar(User user, WireMockExtension wireMock) {
        String expectedAvatarUrl = wireMock.url("/my-avatar.png");
        OicAvatarProperty avatarProperty = user.getProperty(OicAvatarProperty.class);
        assertEquals(expectedAvatarUrl, avatarProperty.getAvatarUrl(), "Avatar url should be " + expectedAvatarUrl);
        assertEquals("OpenID Connect Avatar", avatarProperty.getDisplayName());
        assertNull(avatarProperty.getIconFileName(), "Icon filename must be null");
        String urlViaAvatarResolver = UserAvatarResolver.resolve(user, "48x48");
        assertEquals(expectedAvatarUrl, urlViaAvatarResolver, "Avatar url should be " + expectedAvatarUrl);
    }

    public static void assertTestUserIsMemberOfGroups(User user, String... testUserGroups) {
        for (String group : testUserGroups) {
            assertTrue(user.getAuthorities().contains(group), "User should be part of group " + group);
        }
    }
}

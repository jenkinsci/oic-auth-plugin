package org.jenkinsci.plugins.oic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import hudson.init.InitMilestone;
import hudson.model.User;
import org.jenkinsci.plugins.oic.avatar.AvatarProperty;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

/**
 * On disk compatibility of the relocated avatar user property.
 *
 * <p>
 * The fixtures use the pre-{@code UserIdMapper} {@code users/<id>/config.xml} layout rather than the current
 * {@code users/<prefix>_<hash>/config.xml} one. The hash is an HMAC keyed by the instance's confidential store, so a
 * committed one could only be made to match by also committing key material. {@code UserIdMapper.migrate()} relocates
 * the legacy layout on startup and names {@code @LocalData} as exactly this use case, and both layouts converge on the
 * same {@code User.fixUpAfterLoad()} -> {@code readResolve()} path that is under test here.
 */
@WithJenkins
class AvatarMigrationTest {

    private static final String USER_ID = "jdoe";

    /**
     * Data written by an older release used {@code org.jenkinsci.plugins.oic.OicAvatarProperty}; the
     * {@code @Initializer} registered {@code User.XSTREAM.addCompatibilityAlias(..)} must resolve it
     * to the relocated {@code org.jenkinsci.plugins.oic.avatar.AvatarProperty}.
     */
    @Test
    @LocalData
    void oldOicAvatarPropertyIsMigrated(JenkinsRule j) {
        User user = loadFixtureUser(j);

        AvatarProperty avatarProperty = user.getProperty(AvatarProperty.class);
        assertThat("the legacy avatar property should have been read", avatarProperty, notNullValue());
        assertThat(avatarProperty.getAvatarUrl(), is("https://idp.example.com/avatar/jdoe.png"));
    }

    /**
     * An {@code AvatarProperty} with no data must remove itself while being loaded
     * ({@code readResolve() -> null}).
     */
    @Test
    @LocalData
    void emptyAvatarPropertyIsDroppedOnLoad(JenkinsRule j) {
        User user = loadFixtureUser(j);

        assertThat(user.getProperty(AvatarProperty.class), nullValue());
    }

    /**
     * Resolves the fixture user, so that a fixture that failed to load is not mistaken for broken production
     * behaviour.
     */
    private static User loadFixtureUser(JenkinsRule j) {
        assertThat("Instance is up and running with no errors", j.jenkins.getInitLevel(), is(InitMilestone.COMPLETED));

        User user = User.getById(USER_ID, false);
        assertThat(
                "the fixture user was not loaded from users/" + USER_ID + "/config.xml; a layout that UserIdMapper "
                        + "does not recognise is skipped and logged by User.AllUsers.scanAll",
                user,
                notNullValue());
        assertThat("the fixture should carry a full name, proving it really was read", user.getFullName(), is("J Doe"));
        return user;
    }
}

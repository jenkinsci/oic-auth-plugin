package org.jenkinsci.plugins.oic;

import org.junit.Before;
import org.junit.Test;

import static org.jenkinsci.plugins.oic.OicLogoutAction.POST_LOGOUT_URL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class OicLogoutActionTest {

    private OicLogoutAction action;

    @Before
    public void init() {
        action = new OicLogoutAction();
    }

    @Test
    public void getDisplayName() {
        assertEquals("Oic Logout", action.getDisplayName());
    }

    @Test
    public void getIconFileName() {
        assertNull(action.getIconFileName());
    }

    @Test
    public void getUrlName() {
        assertEquals(POST_LOGOUT_URL, action.getUrlName());
    }

}

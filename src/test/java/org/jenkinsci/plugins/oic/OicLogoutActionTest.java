package org.jenkinsci.plugins.oic;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.jenkinsci.plugins.oic.OicLogoutAction.POST_LOGOUT_URL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class OicLogoutActionTest {

    private OicLogoutAction action;

    @BeforeEach
    void init() {
        action = new OicLogoutAction();
    }

    @Test
    void getIconFileName() {
        assertNull(action.getIconFileName());
    }

    @Test
    void getUrlName() {
        assertEquals(POST_LOGOUT_URL, action.getUrlName());
    }
}

package org.jenkinsci.plugins.oic;

import static org.jenkinsci.plugins.oic.OicLogoutAction.POST_LOGOUT_URL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

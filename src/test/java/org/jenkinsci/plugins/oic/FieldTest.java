package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.api.client.json.GenericJson;
import java.util.HashMap;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;


public class FieldTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(),true);
    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void testNestedLookup() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");

        GenericJson payload = new GenericJson();
        payload.put("email", "myemail@example.com");
        payload.put("user", user);
        payload.put("none", null);

        TestRealm realm = new TestRealm(wireMockRule);

        assertEquals("myemail@example.com", realm.getField(payload, "email"));
        assertEquals("100", realm.getField(payload, "user.id"));
        assertNull(realm.getField(payload, "unknown"));
        assertNull(realm.getField(payload, "user"));
        assertNull(realm.getField(payload, "user.invalid"));
        assertNull(realm.getField(payload, "none"));

        assertTrue(realm.containsField(payload, "email"));
        assertTrue(realm.containsField(payload, "user.id"));
        assertFalse(realm.containsField(payload, "unknown"));
        assertFalse(realm.containsField(payload, "user"));
        assertFalse(realm.containsField(payload, "user.invalid"));
        assertTrue(realm.containsField(payload, "none"));
    }

    @Test
    public void testNormalLookupDueToDot() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");

        GenericJson payload = new GenericJson();
        payload.put("email", "myemail@example.com");
        payload.put("user", user);
        payload.put("none", null);
        payload.put("user.name", "myusername");

        TestRealm realm = new TestRealm(wireMockRule);

        assertEquals("myemail@example.com", realm.getField(payload, "email"));
        assertNull(realm.getField(payload, "unknown"));
        assertNull(realm.getField(payload, "user"));
        assertNull(realm.getField(payload, "user.invalid"));
        assertEquals("myusername", realm.getField(payload, "user.name"));
        assertNull(realm.getField(payload, "none"));

        assertTrue(realm.containsField(payload, "email"));
        assertFalse(realm.containsField(payload, "unknown"));
        assertFalse(realm.containsField(payload, "user"));
        assertFalse(realm.containsField(payload, "user.invalid"));
        assertTrue(realm.containsField(payload, "none"));
        assertTrue(realm.containsField(payload, "user.name"));
    }
}

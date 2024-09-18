package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class FieldTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(new WireMockConfiguration().dynamicPort(), true);

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void testNestedLookup() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");

        Map<String, Object> payload = new HashMap<>();
        payload.put("email", "myemail@example.com");
        payload.put("user", user);
        payload.put("none", null);

        TestRealm realm = new TestRealm(wireMockRule);

        assertEquals("myemail@example.com", realm.getStringFieldFromJMESPath(payload, "email"));
        assertEquals("100", realm.getStringFieldFromJMESPath(payload, "user.id"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "unknown"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user.invalid"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "none"));
    }

    @Test
    public void testNormalLookupDueToDot() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");

        Map<String, Object> payload = new HashMap<>();
        payload.put("email", "myemail@example.com");
        payload.put("user", user);
        payload.put("none", null);
        payload.put("user.name", "myusername");

        TestRealm realm = new TestRealm(wireMockRule);

        assertEquals("myemail@example.com", realm.getStringFieldFromJMESPath(payload, "email"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "unknown"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user.invalid"));
        assertEquals("myusername", realm.getStringFieldFromJMESPath(payload, "\"user.name\""));
        assertNull(realm.getStringFieldFromJMESPath(payload, "none"));
    }

    @Test
    public void testFieldProcessing() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");
        user.put("name", "john");
        user.put("surname", "dow");

        Map<String, Object> payload = new HashMap<>();
        payload.put("user", user);

        TestRealm realm = new TestRealm(wireMockRule);

        assertEquals("john dow", realm.getStringFieldFromJMESPath(payload, "[user.name, user.surname] | join(' ', @)"));
    }

    @Test
    public void testInvalidFieldName() throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("user", "john");

        TestRealm realm = new TestRealm(wireMockRule);

        assertNull(realm.getStringFieldFromJMESPath(payload, "[user)"));
    }
}

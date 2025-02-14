package org.jenkinsci.plugins.oic;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@WithJenkins
class FieldTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort())
            .build();

    @Test
    void testNestedLookup() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");

        Map<String, Object> payload = new HashMap<>();
        payload.put("email", "myemail@example.com");
        payload.put("user", user);
        payload.put("none", null);

        TestRealm realm = new TestRealm(wireMock);

        assertEquals("myemail@example.com", realm.getStringFieldFromJMESPath(payload, "email"));
        assertEquals("100", realm.getStringFieldFromJMESPath(payload, "user.id"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "unknown"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user.invalid"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "none"));
    }

    @Test
    void testNormalLookupDueToDot() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");

        Map<String, Object> payload = new HashMap<>();
        payload.put("email", "myemail@example.com");
        payload.put("user", user);
        payload.put("none", null);
        payload.put("user.name", "myusername");

        TestRealm realm = new TestRealm(wireMock);

        assertEquals("myemail@example.com", realm.getStringFieldFromJMESPath(payload, "email"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "unknown"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user"));
        assertNull(realm.getStringFieldFromJMESPath(payload, "user.invalid"));
        assertEquals("myusername", realm.getStringFieldFromJMESPath(payload, "\"user.name\""));
        assertNull(realm.getStringFieldFromJMESPath(payload, "none"));
    }

    @Test
    void testFieldProcessing() throws Exception {
        HashMap<String, Object> user = new HashMap<>();
        user.put("id", "100");
        user.put("name", "john");
        user.put("surname", "dow");

        Map<String, Object> payload = new HashMap<>();
        payload.put("user", user);

        TestRealm realm = new TestRealm(wireMock);

        assertEquals("john dow", realm.getStringFieldFromJMESPath(payload, "[user.name, user.surname] | join(' ', @)"));
    }

    @Test
    void testInvalidFieldName() throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("user", "john");

        TestRealm realm = new TestRealm(wireMock);

        assertNull(realm.getStringFieldFromJMESPath(payload, "[user)"));
    }
}

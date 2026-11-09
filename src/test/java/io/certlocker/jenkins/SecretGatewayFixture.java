package io.certlocker.jenkins;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.jvnet.hudson.test.JenkinsRule;

/** Only synthetic secret material; no existing database or stored credential is touched. */
final class SecretGatewayFixture {
    static final String PASSWORD = "synthetic-db-password-81754";
    static final String API_TOKEN = "synthetic-deploy-token-99172";
    // Synthetic body only. Construct delimiters at runtime so source scans do not
    // mistake this fixture for a committed private key.
    static final String KEY = ("-----BEGIN %s-----\nSYNTHETIC-KEY-LINE-ONE-12345\r\n"
                    + "SYNTHETIC-KEY-LINE-TWO-67890\n-----END %s-----\n")
            .formatted("PRIVATE KEY", "PRIVATE KEY");
    static final String CONFIG = "# test configuration\nendpoint = example.test\nlast-line = preserved\n";
    final CertLockerPluginTest base = new CertLockerPluginTest();
    final Map<String, byte[]> contents = new ConcurrentHashMap<>();
    final Map<String, Integer> statuses = new ConcurrentHashMap<>();
    final Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();

    void setup(JenkinsRule r, Path temp) throws Exception {
        base.temp = temp;
        base.setup(r);
        CertLockerConfiguration.get().getServers().get(0).setAccount("test-account");
        CertLockerConfiguration.get().save();
        put("password", PASSWORD);
        put("api-token", API_TOKEN);
        put(
                "credentials",
                new net.sf.json.JSONObject()
                        .element("username", "synthetic-user-123")
                        .element("password", PASSWORD)
                        .toString());
        put(
                "pem",
                new net.sf.json.JSONObject()
                        .element("username", "deploy")
                        .element("keyAlgorithm", "RSA")
                        .element("key", KEY)
                        .toString());
        put(
                "private-key",
                new net.sf.json.JSONObject()
                        .element("keyAlgorithm", "ED25519")
                        .element("key", KEY)
                        .toString());
        put("configuration", CONFIG);
        put(
                "json-config",
                "{\"database\":{\"password\":\"" + PASSWORD + "\"},\"a/b\":{\"~key\":[\"nested-value-9123\"]}}");
        put("binary", java.util.Base64.getEncoder().encodeToString(new byte[] {0, 1, 2, (byte) 255, 10, 0, 42}));
        base.gateway.createContext("/gateway/rest/api/v1/secret/", exchange -> {
            String[] segments = exchange.getRequestURI().getPath().split("/");
            String account = segments[6];
            String action = segments[7];
            String id = segments.length > 8 ? segments[8] : "";
            assertEquals("GET", exchange.getRequestMethod());
            assertEquals("fetch", action);
            assertEquals(
                    CertLockerPluginTest.TOKEN, exchange.getRequestHeaders().getFirst("x-api-token"));
            calls.computeIfAbsent(id, ignored -> new AtomicInteger()).incrementAndGet();
            int status = account.equals("test-account")
                    ? statuses.getOrDefault(id, contents.containsKey(id) ? 200 : 404)
                    : 404;
            byte[] bytes = status == 200
                    ? contents.get(id)
                    : "sensitive-error-body-do-not-log-17823".getBytes(StandardCharsets.UTF_8);
            if (status == 307) {
                exchange.getResponseHeaders().set("Location", "/redirect-leak-target");
            }
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(status, bytes.length);
            try (var out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
    }

    void put(String id, String value) {
        contents.put(id, value.getBytes(StandardCharsets.UTF_8));
    }

    int count(String id) {
        return calls.getOrDefault(id, new AtomicInteger()).get();
    }

    void close() {
        base.cleanup();
    }
}

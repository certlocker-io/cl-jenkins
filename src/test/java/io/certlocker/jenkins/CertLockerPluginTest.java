package io.certlocker.jenkins;

import static org.junit.jupiter.api.Assertions.*;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import hudson.EnvVars;
import hudson.model.Result;
import hudson.util.Secret;
import io.jenkins.plugins.oidc_provider.IdTokenStringCredentials;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class CertLockerPluginTest {
    @TempDir
    Path temp;

    private JenkinsRule r;
    HttpsServer gateway;
    private SSLSocketFactory original;
    String url;
    private final AtomicReference<JSONObject> request = new AtomicReference<>();
    private final AtomicReference<String> response = new AtomicReference<>();
    private final AtomicInteger status = new AtomicInteger(200);
    final AtomicInteger calls = new AtomicInteger();
    static final String TOKEN = "test-scoped-token-DO-NOT-LOG-721";

    @BeforeEach
    void setup(JenkinsRule rule) throws Exception {
        r = rule;
        Path store = temp.resolve("tls.p12");
        Process process = new ProcessBuilder(
                        Path.of(System.getProperty("java.home"), "bin", "keytool")
                                .toString(),
                        "-genkeypair",
                        "-alias",
                        "test",
                        "-keyalg",
                        "RSA",
                        "-storetype",
                        "PKCS12",
                        "-keystore",
                        store.toString(),
                        "-storepass",
                        "testpass",
                        "-dname",
                        "CN=localhost",
                        "-ext",
                        "SAN=dns:localhost",
                        "-validity",
                        "2",
                        "-noprompt")
                .redirectErrorStream(true)
                .redirectOutput(temp.resolve("keytool.log").toFile())
                .start();
        assertEquals(0, process.waitFor());
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(store)) {
            keys.load(in, "testpass".toCharArray());
        }
        var km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(keys, "testpass".toCharArray());
        var tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tm.init(keys);
        var ssl = SSLContext.getInstance("TLS");
        ssl.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        original = HttpsURLConnection.getDefaultSSLSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(ssl.getSocketFactory());
        gateway = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        gateway.setHttpsConfigurator(new HttpsConfigurator(ssl));
        response.set(new JSONObject()
                .element("tokenId", TOKEN)
                .element("tokenType", "SECRET")
                .element("expiresAt", Instant.now().plusSeconds(600).toString())
                .toString());
        gateway.createContext("/gateway/rest/api/v1/oidc/exchange", exchange -> {
            calls.incrementAndGet();
            assertEquals("POST", exchange.getRequestMethod());
            request.set(JSONObject.fromObject(
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Location", "/redirect-target");
            byte[] bytes = response.get().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status.get(), bytes.length);
            try (var out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        gateway.start();
        url = "https://localhost:" + gateway.getAddress().getPort() + "/gateway";
        var credential = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "jenkins-oidc", "Test build identity");
        credential.setAudience("https://trust.certlocker.io/oidc/test-account");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), credential);
        CertLockerConfiguration.get().setServers(List.of(new CertLockerServer("test", url, "jenkins-oidc")));
    }

    @AfterEach
    void cleanup() {
        if (gateway != null) {
            gateway.stop(0);
        }
        if (original != null) {
            HttpsURLConnection.setDefaultSSLSocketFactory(original);
        }
    }

    WorkflowJob job(String script) throws Exception {
        WorkflowJob job = r.createProject(WorkflowJob.class);
        job.setDefinition(new CpsFlowDefinition(script, true));
        return job;
    }

    @Test
    void realBuildIdentityExchangeMaskingAndScope() throws Exception {
        WorkflowJob job = job(
                "withEnv(['TRUST_API_TOKEN=outer', 'TRUST_URL=outer-url']) { "
                        + "withCertLockerOIDC(server: 'test') { echo 'bound=' + env.TRUST_API_TOKEN; "
                        + "echo 'url=' + env.TRUST_URL }; echo 'after=' + env.TRUST_API_TOKEN; echo 'url-after=' + env.TRUST_URL }");
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogContains("bound=****", build);
        r.assertLogContains("url=" + url, build);
        r.assertLogContains("after=outer", build);
        r.assertLogContains("url-after=outer-url", build);
        r.assertLogNotContains(TOKEN, build);
        assertEquals(1, calls.get());
        assertEquals("SECRET", request.get().getString("tokenType"));
        String jwt = request.get().getString("idToken");
        r.assertLogNotContains(jwt, build);
        String[] parts = jwt.split("\\.");
        var decoder = Base64.getUrlDecoder();
        JSONObject header = JSONObject.fromObject(new String(decoder.decode(parts[0]), StandardCharsets.UTF_8));
        assertEquals("RS256", header.getString("alg"));
        assertEquals("jenkins-oidc", header.getString("kid"));
        var web = r.createWebClient();
        JSONObject jwks = JSONObject.fromObject(
                web.goTo("oidc/jwks", "application/json").getWebResponse().getContentAsString());
        JSONObject key = jwks.getJSONArray("keys").getJSONObject(0);
        var spec = new RSAPublicKeySpec(
                new BigInteger(1, decoder.decode(key.getString("n"))),
                new BigInteger(1, decoder.decode(key.getString("e"))));
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(KeyFactory.getInstance("RSA").generatePublic(spec));
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(decoder.decode(parts[2])));
        JSONObject claims = JSONObject.fromObject(new String(decoder.decode(parts[1]), StandardCharsets.UTF_8));
        assertEquals(r.getURL() + "oidc", claims.getString("iss"));
        assertEquals(job.getAbsoluteUrl(), claims.getString("sub"));
        assertEquals(1, claims.getInt("build_number"));
        assertTrue(claims.getJSONArray("aud").contains("https://trust.certlocker.io/oidc/test-account"));
        assertTrue(claims.getLong("exp") > Instant.now().getEpochSecond());
    }

    @Test
    void scopeRestoredWhenBodyFails() throws Exception {
        var job = job("withEnv(['TRUST_API_TOKEN=outer']) { try { withCertLockerOIDC(server: 'test') { "
                + "error 'deliberate body failure' } } catch (e) { echo 'after=' + env.TRUST_API_TOKEN } }");
        var build = r.buildAndAssertSuccess(job);
        r.assertLogContains("after=outer", build);
        r.assertLogNotContains(TOKEN, build);
    }

    @Test
    void rejectsUnknownServerWithoutNetwork() throws Exception {
        var build = r.assertBuildStatus(
                Result.FAILURE,
                job("withCertLockerOIDC(server: 'missing') { error 'body ran' }")
                        .scheduleBuild2(0));
        r.assertLogContains("Unknown CertLocker server", build);
        assertEquals(0, calls.get());
    }

    @Test
    void rejectsOrdinarySecretTextCredential() throws Exception {
        var credential = new org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl(
                CredentialsScope.GLOBAL, "static", "not an OIDC identity", Secret.fromString("static-do-not-log"));
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), credential);
        CertLockerConfiguration.get().setServers(List.of(new CertLockerServer("test", url, "static")));
        var build = r.assertBuildStatus(
                Result.FAILURE,
                job("withCertLockerOIDC(server: 'test') { error 'body ran' }").scheduleBuild2(0));
        r.assertLogContains("credential is missing or inaccessible", build);
        r.assertLogNotContains("static-do-not-log", build);
        assertEquals(0, calls.get());
    }

    @Test
    void rejectsUnauthorizedResponseWithoutLeakingBody() throws Exception {
        status.set(401);
        response.set("sensitive-upstream-error-token");
        var build = r.assertBuildStatus(
                Result.FAILURE,
                job("withCertLockerOIDC(server: 'test') { echo 'body-executed' }")
                        .scheduleBuild2(0));
        r.assertLogContains("HTTP 401", build);
        r.assertLogNotContains("sensitive-upstream-error-token", build);
        r.assertLogNotContains("body-executed", build);
    }

    @Test
    void rejectsRedirectAndDoesNotForwardIdentity() throws Exception {
        status.set(307);
        var build = r.assertBuildStatus(
                Result.FAILURE,
                job("withCertLockerOIDC(server: 'test') { echo 'body-executed' }")
                        .scheduleBuild2(0));
        r.assertLogContains("HTTP 307", build);
        assertEquals(1, calls.get());
    }

    @Test
    void rejectsInvalidExpiredAndOversizedResponses() throws Exception {
        for (String invalid : List.of(
                "not-json " + TOKEN,
                new JSONObject()
                        .element("tokenId", TOKEN)
                        .element("tokenType", "SECRET")
                        .element("expiresAt", "2000-01-01T00:00:00Z")
                        .toString(),
                new JSONObject()
                        .element("tokenId", TOKEN)
                        .element("tokenType", "CERTIFICATE")
                        .element("expiresAt", Instant.now().plusSeconds(60).toString())
                        .toString(),
                "x".repeat(65537))) {
            response.set(invalid);
            var build = r.assertBuildStatus(
                    Result.FAILURE,
                    job("withCertLockerOIDC(server: 'test') { echo 'body-executed' }")
                            .scheduleBuild2(0));
            r.assertLogNotContains(TOKEN, build);
            r.assertLogNotContains("body-executed", build);
        }
    }

    @Test
    void untrustedTlsFailsClosed() throws Exception {
        HttpsURLConnection.setDefaultSSLSocketFactory(original);
        var build = r.assertBuildStatus(
                Result.FAILURE,
                job("withCertLockerOIDC(server: 'test') { echo 'body-executed' }")
                        .scheduleBuild2(0));
        r.assertLogContains("TLS trust store", build);
        assertEquals(0, calls.get());
    }

    @Test
    void globalConfigurationRoundTrip() throws Exception {
        r.configRoundtrip();
        var profile = CertLockerConfiguration.get().getServers().get(0);
        assertEquals("test", profile.getName());
        assertEquals(url, profile.getUrl());
        assertEquals("jenkins-oidc", profile.getCredentialsId());
        CertLockerConfiguration.get().load();
        assertEquals(url, CertLockerConfiguration.get().getServers().get(0).getUrl());
    }

    @Test
    void validatesDestinationTypesAndSensitiveEnvironment() throws Exception {
        for (String invalid : List.of(
                "http://localhost",
                "https://user:pass@localhost",
                "https://localhost/?q=x",
                "https://localhost/#x",
                "https://localhost/a/../b",
                "https://localhost:0")) {
            assertThrows(IllegalArgumentException.class, () -> new CertLockerServer("test", invalid, "oidc"));
        }
        var step = new WithCertLockerOIDCStep("test");
        assertThrows(IllegalArgumentException.class, () -> step.setTokenType("ADMIN"));
        assertThrows(
                IllegalArgumentException.class,
                () -> CertLockerConfiguration.get()
                        .setServers(List.of(
                                new CertLockerServer("same", url, "a"), new CertLockerServer("same", url, "b"))));
        var expander = new WithCertLockerOIDCStep.TokenEnvironment(TOKEN, url);
        EnvVars env = new EnvVars();
        expander.expand(env);
        assertEquals(TOKEN, env.get("TRUST_API_TOKEN"));
        assertTrue(expander.getSensitiveVariables().contains("TRUST_API_TOKEN"));
    }

    @Test
    void onlyAdministratorsCanChangeDestinations() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new org.jvnet.hudson.test.MockAuthorizationStrategy()
                .grant(jenkins.model.Jenkins.READ)
                .everywhere()
                .to("reader"));
        try (var context = hudson.security.ACL.as2(
                hudson.model.User.getById("reader", true).impersonate2())) {
            assertThrows(
                    org.springframework.security.access.AccessDeniedException.class,
                    () -> CertLockerConfiguration.get().setServers(List.of()));
        }
        assertEquals(1, CertLockerConfiguration.get().getServers().size());
    }

    @Test
    void acceptsBackendLocalUtcExpiryAndCertificateType() throws Exception {
        response.set(new JSONObject()
                .element("tokenId", TOKEN)
                .element("tokenType", "CERTIFICATE")
                .element(
                        "expiresAt",
                        java.time.LocalDateTime.ofInstant(Instant.now().plusSeconds(600), java.time.ZoneOffset.UTC)
                                .toString())
                .toString());
        var build = r.buildAndAssertSuccess(
                job(
                        "withCertLockerOIDC(server: 'test', tokenType: 'CERTIFICATE') { echo 'bound=' + env.TRUST_API_TOKEN }"));
        assertEquals("CERTIFICATE", request.get().getString("tokenType"));
        r.assertLogContains("bound=****", build);
    }

    @Test
    void administratorCanRemoveLastServerUsingSettingsPage() throws Exception {
        var page = r.createWebClient().goTo("configure");
        var form = page.getFormByName("config");
        var input = form.getInputsByName("_.name").stream()
                .filter(i -> i.getValue().equals("test"))
                .findFirst()
                .orElseThrow();
        org.htmlunit.html.HtmlElement delete = input.getFirstByXPath(
                "ancestor::div[contains(@class,'repeated-chunk')][1]//button[contains(@class,'repeatable-delete')]");
        assertNotNull(delete);
        delete.click();
        r.submit(form);
        assertTrue(CertLockerConfiguration.get().getServers().isEmpty());
    }
}

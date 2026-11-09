package io.certlocker.jenkins;

import static org.junit.jupiter.api.Assertions.*;

import hudson.model.Result;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.test.steps.SemaphoreStep;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class SecretsBindingTest {
    @TempDir
    Path temp;

    private JenkinsRule r;
    private final SecretGatewayFixture gateway = new SecretGatewayFixture();

    @BeforeEach
    void setup(JenkinsRule rule) throws Exception {
        r = rule;
        gateway.setup(r, temp);
    }

    @AfterEach
    void cleanup() {
        gateway.close();
    }

    private WorkflowJob job(String script) throws Exception {
        var job = r.createProject(WorkflowJob.class);
        job.setDefinition(new CpsFlowDefinition(script, true));
        return job;
    }

    private WorkflowRun fail(String script) throws Exception {
        return r.buildAndAssertStatus(Result.FAILURE, job(script));
    }

    private void noLeak(WorkflowRun build) throws Exception {
        for (String secret : List.of(
                SecretGatewayFixture.PASSWORD,
                SecretGatewayFixture.API_TOKEN,
                "SYNTHETIC-KEY-LINE-ONE-12345",
                "SYNTHETIC-KEY-LINE-TWO-67890",
                CertLockerPluginTest.TOKEN,
                "sensitive-error-body-do-not-log-17823")) {
            r.assertLogNotContains(secret, build);
        }
    }

    @Test
    void allTrustTypesMultipleFieldsFilesAndMasking() throws Exception {
        var job = job("node { dir('nested') { withEnv(['DB_PASSWORD=outer']) { "
                + "withCertLockerSecrets(server:'test', secrets:["
                + "[secretId:'password', variable:'DB_PASSWORD'],"
                + "[secretId:'api-token', variable:'DEPLOY_TOKEN'],"
                + "[secretId:'credentials', variable:'DB_USER', field:'username'],"
                + "[secretId:'credentials', variable:'DB_LOGIN_PASSWORD', field:'password'],"
                + "[secretId:'pem', variable:'SSH_KEY', mode:'FILE', field:'key', fileName:'id_rsa'],"
                + "[secretId:'private-key', variable:'TLS_KEY', mode:'FILE', field:'key', fileName:'key.pem'],"
                + "[secretId:'configuration', variable:'CONFIG_FILE', mode:'FILE', fileName:'.app.conf']"
                + "]) { assert env.TRUST_API_TOKEN == null; "
                + "assert env.DB_PASSWORD == env.DB_LOGIN_PASSWORD; assert env.DB_USER == 'synthetic-user-123'; "
                + "assert env.SSH_KEY != env.TLS_KEY; env.KEY_PATH = env.SSH_KEY; env.CONFIG_PATH = env.CONFIG_FILE; "
                + "echo 'password=' + env.DB_PASSWORD; echo 'token=' + env.DEPLOY_TOKEN; "
                + "echo readFile(env.SSH_KEY); echo readFile(env.TLS_KEY); semaphore 'inspect' "
                + "}; assert env.DB_PASSWORD == 'outer'; assert env.SSH_KEY == null; "
                + "assert !fileExists(env.KEY_PATH); assert !fileExists(env.CONFIG_PATH); echo 'scope-restored' } } }");
        var build = job.scheduleBuild2(0).waitForStart();
        SemaphoreStep.waitForStart("inspect/1", build);
        var environment = build.getAction(org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction.class)
                .getEnvironment();
        Path key = Path.of(environment.get("KEY_PATH"));
        Path config = Path.of(environment.get("CONFIG_PATH"));
        assertEquals(".app.conf", config.getFileName().toString());
        assertTrue(
                java.util.Arrays.equals(
                        Files.readAllBytes(key),
                        SecretGatewayFixture.KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                "Key bytes, including mixed line endings, must be preserved");
        assertTrue(
                java.util.Arrays.equals(
                        Files.readAllBytes(config),
                        SecretGatewayFixture.CONFIG.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                "Configuration bytes must be preserved");
        assertFalse(key.startsWith(r.jenkins.getWorkspaceFor(job).getRemote()));
        if (Files.getFileStore(key).supportsFileAttributeView("posix")) {
            assertEquals(
                    "rw-------",
                    java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(key)));
            assertEquals(
                    "rwx------",
                    java.nio.file.attribute.PosixFilePermissions.toString(
                            Files.getPosixFilePermissions(key.getParent().getParent())));
        }
        SemaphoreStep.success("inspect/1", null);
        r.assertBuildStatusSuccess(r.waitForCompletion(build));
        assertFalse(Files.exists(key.getParent().getParent()));
        r.assertLogContains("password=****", build);
        r.assertLogContains("scope-restored", build);
        noLeak(build);
        assertEquals(1, gateway.count("credentials"), "Same secret should be fetched once for multiple fields");
        assertEquals(1, gateway.base.calls.get());
    }

    @Test
    void envOnlyWorksWithoutAgentAndSupportsNestedJsonPointer() throws Exception {
        var build = r.buildAndAssertSuccess(job("withCertLockerSecrets(server:'test', account:'test-account', secrets:["
                + "[secretId:'json-config', variable:'NESTED_PASSWORD', field:'/database/password'],"
                + "[secretId:'json-config', variable:'ESCAPED', field:'/a~1b/~0key/0']]) { "
                + "assert env.ESCAPED == 'nested-value-9123'; echo 'nested=' + env.NESTED_PASSWORD; "
                + "echo 'escaped=' + env.ESCAPED }; assert env.NESTED_PASSWORD == null"));
        r.assertLogContains("nested=****", build);
        r.assertLogNotContains("nested-value-9123", build);
        assertEquals(1, gateway.count("json-config"));
        noLeak(build);
    }

    @Test
    void binaryBase64FileIsExactAndCleanedUpOnBodyFailure() throws Exception {
        var build = r.buildAndAssertSuccess(job("node { try { withCertLockerSecrets(server:'test', secrets:["
                + "[secretId:'binary', variable:'KEYSTORE', mode:'FILE', base64:true, fileName:'client.p12']]) { "
                + "env.SAVED_FILE=env.KEYSTORE; assert readFile(file:env.KEYSTORE, encoding:'Base64') == 'AAEC/woAKg=='; "
                + "error 'deliberate body failure' } } catch (e) { assert !fileExists(env.SAVED_FILE); "
                + "assert env.KEYSTORE == null; echo 'files-cleaned' } }"));
        r.assertLogContains("files-cleaned", build);
        noLeak(build);
    }

    @Test
    void fileBindingsFailBeforeExchangeWithoutNode() throws Exception {
        var build = fail(
                "withCertLockerSecrets(server:'test', secrets:[[secretId:'pem',variable:'KEY',mode:'FILE',field:'key']]) { error 'body-executed' }");
        r.assertLogContains("require a node/agent block", build);
        assertEquals(0, gateway.base.calls.get());
    }

    @Test
    void missingAccountFailsBeforeExchange() throws Exception {
        CertLockerConfiguration.get().getServers().get(0).setAccount(null);
        var build = fail(
                "withCertLockerSecrets(server:'test', secrets:[[secretId:'password',variable:'VALUE']]) { error 'body-executed' }");
        r.assertLogContains("default account", build);
        assertEquals(0, gateway.base.calls.get());
    }

    @Test
    void fetchFailureNeverRunsBodyOrLeaksResponse() throws Exception {
        for (int status : List.of(400, 401, 403, 404, 500, 307)) {
            gateway.statuses.put("password", status);
            var build = fail(
                    "withCertLockerSecrets(server:'test', secrets:[[secretId:'password',variable:'VALUE']]) { echo 'body-executed' }");
            r.assertLogContains("HTTP " + status, build);
            r.assertLogContains("Trust binding VALUE", build);
            r.assertLogNotContains("body-executed", build);
            noLeak(build);
        }
        assertEquals(6, gateway.count("password"));
    }

    @Test
    void partialFetchDoesNotExposeEarlierBindings() throws Exception {
        gateway.statuses.put("api-token", 403);
        var build = r.buildAndAssertSuccess(
                job(
                        "withEnv(['VALUE=outer']) { try { withCertLockerSecrets(server:'test', secrets:["
                                + "[secretId:'password',variable:'VALUE'], [secretId:'api-token',variable:'SECOND']]) { echo 'body-executed' } "
                                + "} catch (e) { assert env.VALUE == 'outer'; assert env.SECOND == null; echo 'partial-safe' } }"));
        r.assertLogContains("partial-safe", build);
        r.assertLogNotContains("body-executed", build);
        noLeak(build);
    }

    @Test
    void invalidFieldNullBase64AndEnvironmentBinaryFailSafely() throws Exception {
        gateway.put("nullable", "{\"password\":null}");
        for (String binding : List.of(
                "[secretId:'credentials',variable:'VALUE',field:'missing']",
                "[secretId:'nullable',variable:'VALUE',field:'password']",
                "[secretId:'json-config',variable:'VALUE',field:'database']",
                "[secretId:'password',variable:'VALUE',base64:true]",
                "[secretId:'binary',variable:'VALUE',base64:true]")) {
            var build =
                    fail("withCertLockerSecrets(server:'test', secrets:[" + binding + "]) { echo 'body-executed' }");
            r.assertLogNotContains("body-executed", build);
            noLeak(build);
        }
    }

    @Test
    void fileCleanupOnCancellation() throws Exception {
        var job = job(
                "node { withCertLockerSecrets(server:'test', secrets:[[secretId:'pem',variable:'KEY',mode:'FILE',field:'key']]) { "
                        + "env.SAVED_FILE=env.KEY; semaphore 'cancel' } }");
        var build = job.scheduleBuild2(0).waitForStart();
        SemaphoreStep.waitForStart("cancel/1", build);
        var environment = build.getAction(org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction.class)
                .getEnvironment();
        Path file = Path.of(environment.get("SAVED_FILE"));
        assertTrue(Files.exists(file));
        build.getExecution().interrupt(Result.ABORTED);
        r.assertBuildStatus(Result.ABORTED, r.waitForCompletion(build));
        assertFalse(Files.exists(file.getParent().getParent()));
        noLeak(build);
    }

    @Test
    void parallelBindingsStayIsolated() throws Exception {
        var build = r.buildAndAssertSuccess(
                job(
                        "parallel left: { withCertLockerSecrets(server:'test', secrets:[[secretId:'password',variable:'VALUE']]) { "
                                + "sleep 1; assert env.VALUE == 'synthetic-db-password-81754'; echo 'left=' + env.VALUE } }, "
                                + "right: { withCertLockerSecrets(server:'test', secrets:[[secretId:'api-token',variable:'VALUE']]) { "
                                + "sleep 1; assert env.VALUE == 'synthetic-deploy-token-99172'; echo 'right=' + env.VALUE } }; assert env.VALUE == null"));
        r.assertLogContains("left=****", build);
        r.assertLogContains("right=****", build);
        noLeak(build);
    }

    @Test
    void unknownServerAndExplicitAccountAreValidated() throws Exception {
        var unknown = fail(
                "withCertLockerSecrets(server:'missing', secrets:[[secretId:'password',variable:'VALUE']]) { echo 'body-executed' }");
        r.assertLogContains("Unknown CertLocker server", unknown);
        assertEquals(0, gateway.base.calls.get());
        var wrong = fail(
                "withCertLockerSecrets(server:'test', account:'different-account', secrets:[[secretId:'password',variable:'VALUE']]) { echo 'body-executed' }");
        r.assertLogContains("HTTP 404", wrong);
        noLeak(wrong);
    }

    @Test
    void emptyAndMultilineEnvironmentValuesArePreserved() throws Exception {
        gateway.put("empty", "");
        var build = r.buildAndAssertSuccess(job("withCertLockerSecrets(server:'test', secrets:["
                + "[secretId:'empty',variable:'EMPTY_VALUE'],[secretId:'configuration',variable:'CONFIG_TEXT']]) { "
                + "assert env.CONFIG_TEXT.endsWith('\\n'); echo env.CONFIG_TEXT; assert env.EMPTY_VALUE == null || env.EMPTY_VALUE == ''; "
                + "echo 'multiline-ok' }"));
        r.assertLogContains("multiline-ok", build);
        r.assertLogNotContains("last-line = preserved", build);
    }

    @Test
    void duplicateInvalidVariablesAndPathsAreRejected() throws Exception {
        for (String variable : List.of("BAD-NAME", "PATH", "TRUST_API_TOKEN", "", "1BAD")) {
            assertThrows(IllegalArgumentException.class, () -> new SecretBinding("password", variable));
        }
        for (String id : List.of("../escape", "x/y", "x?token=y", "x#fragment", "x%2Fy")) {
            assertThrows(IllegalArgumentException.class, () -> new SecretBinding(id, "VALUE"));
        }
        var binding = new SecretBinding("pem", "KEY");
        assertThrows(IllegalArgumentException.class, () -> binding.setFileName("../key.pem"));
        assertThrows(IllegalArgumentException.class, () -> binding.setMode("UNKNOWN"));
        assertThrows(
                IllegalArgumentException.class, () -> new WithCertLockerSecretsStep("test", List.of(binding, binding)));
        assertThrows(IllegalArgumentException.class, () -> new WithCertLockerSecretsStep("test", List.of()));
    }

    @Test
    void rejectsOversizedFetchAndEnvironmentValues() throws Exception {
        gateway.contents.put("large", new byte[TrustSecretClient.MAX_SECRET_BYTES + 1]);
        var oversized = fail(
                "withCertLockerSecrets(server:'test', secrets:[[secretId:'large',variable:'VALUE']]) { echo 'body-executed' }");
        r.assertLogContains("4 MiB fetch limit", oversized);
        gateway.put("large-env", "x".repeat(65537));
        var env = fail(
                "withCertLockerSecrets(server:'test', secrets:[[secretId:'large-env',variable:'VALUE']]) { echo 'body-executed' }");
        r.assertLogContains("use mode FILE", env);
        r.assertLogNotContains("body-executed", env);
    }

    @Test
    void fileBindingRunsOnRealAgentAndCleansUp() throws Exception {
        var agent = r.createOnlineSlave();
        var job = job("node('" + agent.getNodeName() + "') { withCertLockerSecrets(server:'test', secrets:["
                + "[secretId:'pem',variable:'KEY',field:'key',mode:'FILE',fileName:'deploy.pem']]) { "
                + "env.SAVED_FILE=env.KEY; semaphore 'agent-inspect'; echo readFile(env.KEY) "
                + "}; assert !fileExists(env.SAVED_FILE); echo 'agent-cleaned' }");
        var build = job.scheduleBuild2(0).waitForStart();
        SemaphoreStep.waitForStart("agent-inspect/1", build);
        var environment = build.getAction(org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction.class)
                .getEnvironment();
        var file = new hudson.FilePath(agent.getChannel(), environment.get("SAVED_FILE"));
        assertTrue(file.exists());
        assertTrue(
                java.util.Arrays.equals(
                        file.readToString().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        SecretGatewayFixture.KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                "Agent receives the original key material");
        SemaphoreStep.success("agent-inspect/1", null);
        r.assertBuildStatusSuccess(r.waitForCompletion(build));
        assertFalse(file.exists());
        r.assertLogContains("agent-cleaned", build);
        noLeak(build);
    }

    @Test
    void serverDefaultAccountPersistsThroughSettingsUi() throws Exception {
        r.configRoundtrip();
        assertEquals(
                "test-account",
                CertLockerConfiguration.get().getServers().get(0).getAccount());
    }

    @Test
    void snippetGeneratorProducesRunnableBindingsWithBlankOptionalFilename() throws Exception {
        var binding = new SecretBinding("credentials", "DB_PASSWORD");
        binding.setField("password");
        binding.setFileName("");
        assertNull(binding.getFileName());
        var step = new WithCertLockerSecretsStep("test", List.of(binding));
        String snippet = org.jenkinsci.plugins.workflow.cps.Snippetizer.object2Groovy(step);
        assertTrue(snippet.contains("withCertLockerSecrets"));
        assertTrue(snippet.contains("DB_PASSWORD"));
        var build = r.buildAndAssertSuccess(job(snippet));
        assertEquals(1, gateway.count("credentials"));
        noLeak(build);
    }
}

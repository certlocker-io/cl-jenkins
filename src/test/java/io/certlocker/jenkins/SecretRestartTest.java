package io.certlocker.jenkins;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.test.steps.SemaphoreStep;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.junit.jupiter.JenkinsSessionExtension;

class SecretRestartTest {
    @RegisterExtension
    final JenkinsSessionExtension sessions = new JenkinsSessionExtension();

    @Test
    void secretVariablesAndFilesResumeAndCleanUpAfterControllerRestart() throws Throwable {
        var fixture = new SecretGatewayFixture();
        Path temp = Files.createTempDirectory("trust-secret-restart-test");
        var name = new AtomicReference<String>();
        var file = new AtomicReference<Path>();
        try {
            sessions.then(r -> {
                fixture.setup(r, temp);
                var job = fixture.base.job(
                        "node { withCertLockerSecrets(server:'test', secrets:["
                                + "[secretId:'password',variable:'DB_PASSWORD'],"
                                + "[secretId:'pem',variable:'KEY_FILE',mode:'FILE',field:'key']]) { "
                                + "env.SAVED_FILE=env.KEY_FILE; semaphore 'secret-restart'; "
                                + "echo 'resumed=' + env.DB_PASSWORD; echo readFile(env.KEY_FILE) "
                                + "}; assert !fileExists(env.SAVED_FILE); assert env.DB_PASSWORD == null; echo 'cleaned-after-restart' }");
                name.set(job.getFullName());
                var build = job.scheduleBuild2(0).waitForStart();
                SemaphoreStep.waitForStart("secret-restart/1", build);
                var environment = build.getAction(
                                org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction.class)
                        .getEnvironment();
                file.set(Path.of(environment.get("SAVED_FILE")));
                assertTrue(Files.exists(file.get()));
            });
            sessions.then(r -> {
                var job = r.jenkins.getItemByFullName(name.get(), WorkflowJob.class);
                WorkflowRun build = job.getBuildByNumber(1);
                Path state = build.getRootDir().toPath().resolve("program.dat");
                String persisted = new String(Files.readAllBytes(state), java.nio.charset.StandardCharsets.ISO_8859_1);
                for (String secret : java.util.List.of(
                        SecretGatewayFixture.PASSWORD, "SYNTHETIC-KEY-LINE-ONE-12345", CertLockerPluginTest.TOKEN)) {
                    assertFalse(persisted.contains(secret), "Secret values must not be persisted in plaintext");
                }
                assertTrue(Files.exists(file.get()));
                SemaphoreStep.success("secret-restart/1", null);
                r.assertBuildStatusSuccess(r.waitForCompletion(build));
                r.assertLogContains("resumed=****", build);
                r.assertLogContains("cleaned-after-restart", build);
                r.assertLogNotContains(SecretGatewayFixture.PASSWORD, build);
                r.assertLogNotContains("SYNTHETIC-KEY-LINE-ONE-12345", build);
                assertFalse(Files.exists(file.get().getParent().getParent()));
                assertEquals(1, fixture.count("password"));
                assertEquals(1, fixture.base.calls.get(), "Resumption must not reissue a token");
            });
        } finally {
            fixture.close();
            try (var paths = Files.walk(temp)) {
                for (Path path :
                        paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
            if (file.get() != null && Files.exists(file.get())) {
                try (var paths = Files.walk(file.get().getParent().getParent())) {
                    for (Path path :
                            paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                        Files.deleteIfExists(path);
                    }
                }
            }
        }
    }
}

package io.certlocker.jenkins;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.test.steps.SemaphoreStep;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.junit.jupiter.JenkinsSessionExtension;

class PipelineRestartTest {
    @RegisterExtension
    final JenkinsSessionExtension sessions = new JenkinsSessionExtension();

    @Test
    void tokenSurvivesControllerRestartEncryptedAndMasked() throws Throwable {
        var fixture = new CertLockerPluginTest();
        fixture.temp = Files.createTempDirectory("certlocker-restart-tls");
        AtomicInteger number = new AtomicInteger();
        var name = new java.util.concurrent.atomic.AtomicReference<String>();
        try {
            sessions.then(r -> {
                fixture.setup(r);
                WorkflowJob job = fixture.job(
                        "withCertLockerOIDC(server: 'test') { semaphore 'inside'; "
                                + "echo 'resumed=' + env.TRUST_API_TOKEN }; echo 'outside=' + (env.TRUST_API_TOKEN ?: 'absent')");
                WorkflowRun build = job.scheduleBuild2(0).waitForStart();
                number.set(build.getNumber());
                name.set(job.getFullName());
                SemaphoreStep.waitForStart("inside/1", build);
            });
            sessions.then(r -> {
                WorkflowJob job = r.jenkins.getItemByFullName(name.get(), WorkflowJob.class);
                assertNotNull(job);
                WorkflowRun build = job.getBuildByNumber(number.get());
                assertTrue(build.isBuilding());
                Path state = build.getRootDir().toPath().resolve("program.dat");
                assertTrue(Files.exists(state));
                assertFalse(
                        new String(Files.readAllBytes(state), java.nio.charset.StandardCharsets.ISO_8859_1)
                                .contains(CertLockerPluginTest.TOKEN),
                        "Pipeline must not persist a plaintext token");
                SemaphoreStep.success("inside/1", null);
                r.assertBuildStatusSuccess(r.waitForCompletion(build));
                r.assertLogContains("resumed=****", build);
                r.assertLogContains("outside=absent", build);
                r.assertLogNotContains(CertLockerPluginTest.TOKEN, build);
            });
        } finally {
            fixture.cleanup();
            try (var paths = Files.walk(fixture.temp)) {
                for (Path path :
                        paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }
}

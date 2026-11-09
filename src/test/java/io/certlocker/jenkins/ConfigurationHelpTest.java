package io.certlocker.jenkins;

import static org.junit.jupiter.api.Assertions.*;

import hudson.util.FormValidation;
import java.util.List;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ConfigurationHelpTest {
    @Test
    void serverInstructionsAreVisibleWithoutFetchingHelp(JenkinsRule r) throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin"));
        CertLockerConfiguration.get()
                .setServers(List.of(new CertLockerServer(
                        "local-trust", "https://trust.example.com/gateway", "certlocker-build-identity")));
        var page = r.createWebClient().login("admin").goTo("configure");
        String text = page.asNormalizedText();
        assertTrue(text.contains("spaces are not allowed"));
        assertTrue(text.contains("a local HTTP server needs an HTTPS reverse proxy"));
        assertTrue(text.contains("Create an OpenID Connect id token (string) credential"));
        assertTrue(text.contains("not its display name"));
        assertTrue(page.getByXPath("//a[contains(@href, 'io.certlocker.jenkins.CertLockerServer/help/')]")
                .isEmpty());
        assertTrue(page.getByXPath(
                        "//*[@data-url and contains(@data-url, 'io.certlocker.jenkins.CertLockerServer/help/')]")
                .isEmpty());
    }

    @Test
    void invalidConfigurationIsReportedBeforeSubmitting(JenkinsRule r) {
        var descriptor = r.jenkins.getDescriptorByType(CertLockerServer.DescriptorImpl.class);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckName("Local Trust").kind);
        assertEquals(FormValidation.Kind.OK, descriptor.doCheckName("local-trust").kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckUrl("http://localhost:8090/gateway").kind);
        assertEquals(FormValidation.Kind.OK, descriptor.doCheckUrl("https://trust.example.com/gateway").kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckCredentialsId("").kind);
        assertEquals(FormValidation.Kind.OK, descriptor.doCheckCredentialsId("certlocker-build-identity").kind);
        assertEquals(FormValidation.Kind.OK, descriptor.doCheckAccount("").kind);
        assertEquals(FormValidation.Kind.ERROR, descriptor.doCheckAccount("https://trust.example.com/account").kind);
    }

    @Test
    void authenticatedAdministratorCanReadAllServerHelp(JenkinsRule r) throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin"));
        var web = r.createWebClient().login("admin");
        for (String field : List.of("url", "credentialsId", "account")) {
            var page = web.goTo("descriptorByName/io.certlocker.jenkins.CertLockerServer/help/" + field);
            assertEquals(200, page.getWebResponse().getStatusCode());
            assertFalse(page.getWebResponse().getContentAsString().isBlank());
        }
    }
}

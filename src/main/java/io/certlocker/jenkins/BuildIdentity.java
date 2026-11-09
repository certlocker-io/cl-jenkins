package io.certlocker.jenkins;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.AbortException;
import hudson.model.Run;
import io.jenkins.plugins.oidc_provider.IdTokenStringCredentials;
import java.io.IOException;
import java.util.List;

final class BuildIdentity {
    record Identity(String jwt, String token) {
        // Deliberately omit record-generated toString: neither token may reach logs.
        @Override
        public String toString() {
            return "CertLocker build identity (redacted)";
        }
    }

    static Identity exchange(CertLockerServer profile, Run<?, ?> build, String tokenType) throws IOException {
        IdTokenStringCredentials credential = CredentialsProvider.findCredentialById(
                profile.getCredentialsId(), IdTokenStringCredentials.class, build, List.of());
        if (credential == null) {
            throw new AbortException("CertLocker OIDC provider credential is missing or inaccessible to this build");
        }
        String jwt;
        try {
            jwt = ((IdTokenStringCredentials) credential.forRun(build))
                    .getSecret()
                    .getPlainText();
        } catch (RuntimeException e) {
            throw new AbortException(
                    "Unable to create build OIDC identity; check Jenkins OIDC provider issuer, audience and claim configuration");
        }
        return new Identity(jwt, new ExchangeClient().exchange(profile, jwt, tokenType));
    }
}

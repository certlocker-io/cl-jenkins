package io.certlocker.jenkins;

import hudson.AbortException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;

/** Fetches the raw, access-controlled Gateway payload; never uses the metadata endpoint. */
final class TrustSecretClient {
    static final int MAX_SECRET_BYTES = 4 * 1024 * 1024;

    byte[] fetch(CertLockerServer profile, String account, String id, String token) throws IOException {
        CertLockerServer.endpoint(profile.getUrl());
        var url = URI.create(profile.getUrl() + "/rest/api/v1/secret/" + SecretBinding.pathId(account) + "/fetch/"
                        + SecretBinding.pathId(id))
                .toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(30000);
            connection.setRequestProperty("Accept", "text/plain");
            connection.setRequestProperty("x-api-token", token);
            int status = connection.getResponseCode();
            if (status != 200) {
                String help = switch (status) {
                    case 401 ->
                        "Identity expired or additional interactive authentication is required; configure a non-interactive build principal.";
                    case 403 -> "The build principal is not permitted to access this secret.";
                    case 404 -> "Check the account and secret ID, and the principal permissions.";
                    case 400 -> "Check the account, secret ID, status and principal permissions.";
                    case 301, 302, 303, 307, 308 ->
                        "Redirects are refused; configure the final Gateway HTTPS base URL.";
                    default -> "Check Gateway availability and the build principal permissions.";
                };
                throw new AbortException("Trust secret fetch failed (HTTP " + status + "). " + help);
            }
            try (var in = connection.getInputStream()) {
                byte[] bytes = in.readNBytes(MAX_SECRET_BYTES + 1);
                if (bytes.length > MAX_SECRET_BYTES) {
                    throw new AbortException("Trust secret exceeds the 4 MiB fetch limit");
                }
                return bytes;
            }
        } catch (AbortException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new AbortException(
                    "Unable to fetch Trust secret. Check connectivity and the controller JVM TLS trust store.");
        } finally {
            connection.disconnect();
        }
    }
}

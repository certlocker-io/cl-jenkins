package io.certlocker.jenkins;

import hudson.AbortException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.Set;
import net.sf.json.JSONObject;

/** No credential-bearing request or response is included in an exception. */
final class ExchangeClient {
    static final Set<String> TOKEN_TYPES = Set.of("SECRET", "CERTIFICATE", "MCP");
    private static final int MAX_RESPONSE = 65536;

    String exchange(CertLockerServer server, String idToken, String tokenType) throws IOException {
        HttpURLConnection connection = (HttpURLConnection)
                CertLockerServer.endpoint(server.getUrl()).toURL().openConnection();
        try {
            connection.setRequestMethod("POST");
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(30000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            connection.setRequestProperty("Accept", "application/json");
            byte[] body = new JSONObject()
                    .element("idToken", idToken)
                    .element("tokenType", tokenType)
                    .toString()
                    .getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            try (var out = connection.getOutputStream()) {
                out.write(body);
            }
            int status = connection.getResponseCode();
            if (status != 200) {
                throw new AbortException("CertLocker OIDC exchange failed (HTTP " + status
                        + "). Check the registered Jenkins principal and its permissions.");
            }
            byte[] response;
            try (var in = connection.getInputStream()) {
                response = in.readNBytes(MAX_RESPONSE + 1);
            }
            if (response.length > MAX_RESPONSE) {
                throw new AbortException("CertLocker OIDC exchange response exceeds the size limit");
            }
            try {
                JSONObject json = JSONObject.fromObject(new String(response, StandardCharsets.UTF_8));
                Object value = json.get("tokenId");
                if (!(value instanceof String token)
                        || token.isBlank()
                        || token.length() > 8192
                        || token.chars().anyMatch(Character::isWhitespace)
                        || !tokenType.equals(json.getString("tokenType"))) {
                    throw new IllegalArgumentException();
                }
                String expiry = json.getString("expiresAt");
                Instant expires;
                try {
                    expires = Instant.parse(expiry);
                } catch (DateTimeParseException ignored) {
                    expires = LocalDateTime.parse(expiry).toInstant(ZoneOffset.UTC);
                }
                if (!expires.isAfter(Instant.now())) {
                    throw new IllegalArgumentException();
                }
                return token;
            } catch (RuntimeException e) {
                throw new AbortException("CertLocker returned an invalid or expired OIDC exchange response");
            }
        } catch (AbortException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new AbortException(
                    "Unable to exchange Jenkins OIDC identity with CertLocker. Check connectivity and the controller JVM TLS trust store.");
        } finally {
            connection.disconnect();
        }
    }
}

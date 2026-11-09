# Changes

## 0.2.0

- Add `withCertLockerSecrets` with multiple named bindings and automatic build OIDC authentication.
- Support all current Trust secret payloads: PASSWORD, CREDENTIALS, CONFIGURATION, PEM and PRIVATE_KEY.
- Bind text to masked environment variables or exact bytes to private agent-side temporary files.
- Select JSON fields/nested pointers and optionally decode Base64 for binary files.
- Add per-server default accounts, selectable server profiles and binding forms in Pipeline Syntax.
- Preserve surrounding environment and clean up files after success, failure, cancellation and normal restart/resumption.
- Fetch each secret once within a block, fail before entering the body if any required binding fails,
  and report the failed variable without including response bodies or secret contents.
- Keep `withCertLockerOIDC` for direct Trust API access and all its existing token types.
- Add examples and Jenkins tests covering all secret types, exact bytes, masking, parallel scopes,
  cancellation, restart, a remoting agent, negative responses and runnable generated snippets.
- Show server setup instructions inline and validate configuration fields before saving.
- Publish verified, versioned HPI downloads and SHA-256 checksums through GitHub Releases.

## 0.1.0-SNAPSHOT

- Initial standalone Jenkins HPI with administrator-controlled server profiles and
  `withCertLockerOIDC` for scoped build authentication.

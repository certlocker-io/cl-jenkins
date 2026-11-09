# Security policy

## Reporting a vulnerability

Do not disclose credentials, private keys, secret values or an unpatched vulnerability in
a public issue or pull request. Use this repository's GitHub **Security → Report a
vulnerability** option when private vulnerability reporting is enabled. Otherwise contact
CertLocker through [certlocker.io](https://certlocker.io) to arrange private disclosure.

Include the plugin, Jenkins and Java versions, a description of the affected behavior,
and a minimal reproduction using synthetic data. Explain the expected impact without
including live tokens, private keys or customer data.

## Security behavior

The plugin uses build-scoped OIDC credentials, administrator-controlled HTTPS destinations,
Trust's access-controlled secret-fetch API and scoped Pipeline bindings. TLS validation is
enabled and redirects are refused. Fetched secrets are not copied into Jenkins' permanent
credentials store.

Console masking cannot protect against deliberate disclosure, transformed values or other
processes running under the same agent account. File cleanup cannot be guaranteed after
permanent agent loss or a hard kill during setup. Use least-privilege Trust principals and
isolated agents. See the [usage guide](docs/usage.md#security-cleanup-and-lifetime) for the
full lifetime, persistence and cleanup behavior.

## Releases

This project currently uses development snapshot versions. Fixes are made on the default
branch; historical snapshot builds are not maintained as separate security release lines.

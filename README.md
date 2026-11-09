# CertLocker Jenkins Plugin

Use secrets from CertLocker Trust in Jenkins Pipeline builds. The plugin authenticates each
build with OpenID Connect (OIDC), fetches the requested secrets and binds them to environment
variables or private temporary files. A static Trust API key is not required.

Supported Trust secret types include passwords, credentials, configuration, PEMs and private
keys. Stored deployment tokens and Base64-encoded binary files are supported too.

## Documentation

- [Installation and configuration](docs/configuration.md)
- [Secret types, binding options and Pipeline recipes](docs/usage.md)
- [Complete example Jenkinsfile](examples/Jenkinsfile)
- [Contributing and running tests](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Example

Once a server profile named `production` has been configured:

```groovy
node {
    withCertLockerSecrets(server: 'production', secrets: [
        [secretId: 'database-secret-id', variable: 'DB_PASSWORD'],
        [secretId: 'deployment-token-id', variable: 'DEPLOY_TOKEN'],
        [secretId: 'ssh-key-secret-id', variable: 'SSH_KEY',
         field: 'key', mode: 'FILE', fileName: 'deploy.pem']
    ]) {
        sh './deploy.sh'
    }
}
```

Replace the example secret IDs with your Trust secret IDs. Inside the block, `DB_PASSWORD`
and `DEPLOY_TOKEN` contain their secret values, and `SSH_KEY` contains a temporary file path.
The deployment script reads those environment variables. Values are masked in the block's
console output; bindings are restored and temporary files removed when the block finishes.

The block can retrieve several secrets in one authentication exchange. JSON field selection
supports username/password credentials, nested configuration and the `key` property of
Trust-generated PEM and private-key secrets. See the [usage guide](docs/usage.md) for examples.

## Requirements

| Component | Requirement |
| --- | --- |
| Jenkins | 2.568.1 or newer |
| Java | 21 or 25; Java 21 is used for automated tests |
| OpenID Connect Provider plugin | 234.vca_b_26b_f4b_dda_ or newer |
| Trust | A deployment supporting Jenkins OIDC principals and the Gateway secret-fetch API |
| Network | HTTPS connectivity from Jenkins to Trust, and from Trust to the Jenkins issuer's public JWKS |

The HPI declares its required Jenkins plugin dependencies. This repository provides a
Pipeline plugin; it does not provide a Freestyle build wrapper.

## Build and install

Select Java 21, then run:

```sh
./mvnw -B clean verify
```

Upload `target/certlocker.hpi` through **Manage Jenkins → Plugins → Advanced settings →
Deploy Plugin**, then restart Jenkins if requested. Install OpenID Connect Provider and
the Pipeline dependencies before uploading an HPI manually.

The plugin is not currently distributed through the Jenkins update centre. See the
[configuration guide](docs/configuration.md) for dependency installation, issuer setup,
Trust permissions, server profiles and a first-build check.

## Licence

[MIT](LICENSE). Third-party licence notices are retained in the source and Maven Wrapper.

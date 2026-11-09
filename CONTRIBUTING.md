# Contributing

Use Java 21 and the checked-in Maven Wrapper. You do not need a running Trust deployment
or production credentials to build or test this plugin.

```sh
./mvnw -B clean verify
```

The build runs Jenkins integration tests and SpotBugs and creates `target/certlocker.hpi`.
Tests use disposable Jenkins controllers, an HTTPS Gateway fixture and synthetic secrets.
They cover signed build identities, secret bindings, file permissions, masking, cleanup,
parallel execution, controller restarts and a remoting agent. The generated localisation
check is skipped when there are no localisation properties files.

Format Java and POM changes before submitting:

```sh
./mvnw -B spotless:apply
```

For a disposable development controller on port 8081:

```sh
./mvnw hpi:run -Djetty.port=8081
```

Use the [configuration guide](docs/configuration.md) for actual Trust integration. Real
exchanges require a reachable HTTPS issuer; the local development controller's HTTP URL
is not sufficient on its own.

## Pull requests

Explain the behavior being changed, include relevant tests, and update documentation or
examples when Pipeline options change. Keep unrelated changes in separate pull requests.
Use synthetic secret material in tests and examples; never commit credentials, `.env`
files, customer data, private keys, local controller state or generated build output.

Screenshots can be added alongside the configuration guide under `docs/images/`. Use a
demonstration environment and redact real secret values, tokens, private keys and customer
information. Keep images small and add descriptive alternative text when linking them.
Do not add placeholder images or links for screenshots that are not yet available.

Report security issues privately using the [security policy](SECURITY.md).

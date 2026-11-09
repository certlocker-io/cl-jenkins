# Installing and configuring the plugin

[Plugin overview](../README.md) · [Pipeline recipes and options](usage.md)

This guide connects Jenkins to CertLocker Trust using a build's OpenID Connect identity.
Jenkins signs a short-lived identity token, Trust checks it against a registered principal,
and the plugin uses the resulting Trust access token to fetch the requested secrets.

## 1. Check the prerequisites

You need administrator access to Jenkins and permission to manage OIDC principals in the
Trust account that owns the secrets.

| Component | Requirement |
| --- | --- |
| Jenkins controller | 2.568.1 or newer |
| Java | 21 or 25; use Java 21 when building this plugin |
| Jenkins plugins | OpenID Connect Provider, Pipeline and Credentials Binding, with their dependencies |
| Trust | Jenkins OIDC principal support, OIDC exchange and the Gateway secret-fetch API |
| Jenkins → Trust | The controller can reach the Gateway over HTTPS and trusts its TLS certificate |
| Trust → Jenkins | Trust can reach the issuer's public HTTPS JWKS endpoint and trusts its TLS certificate |

Secret-file bindings also require an allocated Jenkins agent (`node` in Scripted Pipeline,
or an `agent` in Declarative Pipeline). ENV-only bindings can execute without an agent.

The examples below use these placeholders:

| Setting | Example |
| --- | --- |
| Jenkins public URL | `https://jenkins.example.com/` |
| Trust Gateway base URL | `https://trust.example.com` |
| Trust account ID | `your-account-id` |
| Jenkins OIDC credential ID | `certlocker-build-identity` |
| Plugin server profile | `production` |
| Example job URL | `https://jenkins.example.com/job/release/` |

Replace them with your deployment's values. If your Gateway is served under a context path,
include that path in its base URL, for example `https://trust.example.com/gateway`.
Do not add `/rest/api/v1` to the base URL; the plugin adds the API path.

## 2. Build and install the HPI

With Java 21 selected, run from the repository root:

```sh
./mvnw -B clean verify
```

On Windows, use `mvnw.cmd -B clean verify`. The installable file is `target/certlocker.hpi`.

In Jenkins:

1. Open **Manage Jenkins → Plugins → Available plugins**.
2. Install **OpenID Connect Provider**, **Pipeline** and **Credentials Binding** if needed.
   Jenkins resolves their dependencies through its update centre.
3. Open **Advanced settings**, find **Deploy Plugin**, select `certlocker.hpi` and upload it.
4. Restart Jenkins if requested. Confirm **CertLocker Jenkins Plugin** is listed under
   **Installed plugins** and is enabled.

The HPI requires OpenID Connect Provider **234.vca_b_26b_f4b_dda_ or newer**. If Jenkins
reports an unmet dependency, install the version required by the uploaded HPI manifest.
Uploading an HPI manually does not reliably install its dependencies for you.

## 3. Set Jenkins' public URL

Open **Manage Jenkins → System → Jenkins Location** and set **Jenkins URL** to the public
HTTPS URL, including any context path and its trailing slash. Save the configuration.

For a root-level Jenkins instance, the default issuer is:

```text
https://jenkins.example.com/oidc
```

For Jenkins served under `/jenkins/`, it is normally:

```text
https://jenkins.example.com/jenkins/oidc
```

The issuer has no trailing slash. A wrong Jenkins URL changes the issuer and default job
subject, so fix the root URL before registering a Trust principal.

## 4. Create the Jenkins OIDC credential

Open **Manage Jenkins → Credentials**, select an appropriate store/domain, and choose
**Add Credentials**. The usual global store is **System → Global credentials (unrestricted)**.

Set these values:

| Field | Value |
| --- | --- |
| Kind | **OpenID Connect id token**, the string credential type |
| Scope | **Global**, so jobs can use it; not the System-only scope |
| ID | `certlocker-build-identity` |
| Description | A description identifying its Trust account or workload |
| Issuer | Leave the override blank to use the provider's issuer, unless you intentionally serve an alternate issuer |
| Audience | The exact audience you will register in Trust |

The usual per-account audience is:

```text
https://trust.certlocker.io/oidc/your-account-id
```

The audience is an identifier and must match exactly on both sides. It does not need to
be the URL of your own Gateway. If your Trust principal uses a custom audience, use that
same custom value in Jenkins.

The provider manages the signing key. You do not need to enter a Trust API token, private
key or client secret into the CertLocker server profile. Ordinary **Secret text** credentials
are not accepted as the OIDC credential.

Folder-scoped credentials are supported when visible to the build. They can have a
folder-specific issuer; use the issuer reported by the provider rather than assuming the
root `/oidc` issuer. The Jenkins and Trust administrators must agree on that exact issuer.

## 5. Verify the public issuer metadata

From a machine with the same network access as Trust, check the issuer's discovery document
and public keys. For the example root issuer:

```sh
curl --fail --silent --show-error \
  https://jenkins.example.com/oidc/.well-known/openid-configuration

curl --fail --silent --show-error \
  https://jenkins.example.com/oidc/jwks
```

The discovery document should report the expected issuer and JWKS URI. The JWKS contains
public signing keys, not private key material. The OIDC provider makes its public metadata
endpoints available without a Jenkins login. Ensure a reverse proxy or authentication
layer does not replace these responses with a sign-in page.

Keep TLS verification enabled. For private CAs, configure the appropriate JVM trust stores
on Jenkins and Trust. A localhost HTTP development controller alone is insufficient for a
real Trust exchange: the Trust Jenkins verifier requires an HTTPS issuer.

## 6. Register a Jenkins principal in Trust

In the target Trust account, open **OIDC principals** and create a principal with provider
**Jenkins** (`JENKINS`). Configure:

| Setting | Value |
| --- | --- |
| Issuer | The exact issuer checked in step 5 |
| Audience | The exact audience configured on the Jenkins credential |
| Allowed token types | Include `SECRET` for `withCertLockerSecrets` |
| Default token type | `SECRET` for a secrets-only principal |
| Jenkins job / subject rule | The build token's exact `sub` claim |
| Allowed groups | Only the groups containing secrets this workload needs |
| Token lifetime | Long enough for the exchange and secret fetches; keep it short |

Make the principal active. An empty allowed-groups list means unrestricted group access
in Trust; select groups explicitly when a build should have restricted access. Builds
must use non-interactive access rather than a principal/token requiring a human OTP or
access code.

### Use the correct job subject

By default, OpenID Connect Provider sets `sub` to the **absolute job URL**, including its
trailing slash. For the example release job, the value is:

```text
https://jenkins.example.com/job/release/
```

For a job inside a folder, it could be:

```text
https://jenkins.example.com/job/team/job/release/
```

Enter that full value in Trust's Jenkins job/subject rule, even if the field is labelled
**Jenkins job**. A job name such as `release` does not match the provider's default subject.
The default build identity also includes a `build_number` claim.

If you deliberately change the provider's claim templates under **Manage Jenkins → Security →
OpenID Connect**, the Trust rule must match the subject actually issued. Leave branch rules
unset unless the provider is configured to issue the corresponding trusted `branch` claim;
the plugin does not add it automatically. For multibranch jobs, each branch is a Jenkins
job and must match the configured principal rules.

## 7. Add a CertLocker server profile in Jenkins

Open **Manage Jenkins → System → CertLocker**, add a server and fill in:

| Field | Example | Purpose |
| --- | --- | --- |
| Name | `production` | The profile name used in Jenkinsfiles |
| CertLocker base URL (HTTPS) | `https://trust.example.com` | Gateway base URL, including any context path |
| OpenID Connect id token credential ID | `certlocker-build-identity` | The credential created in step 4 |
| Default Trust account ID | `your-account-id` | Account used unless a Pipeline sets `account` explicitly |

Save the configuration. Server names must be unique. You can configure several profiles
for different Trust instances, accounts or workload identities.

Use a Pipeline-friendly name such as `local-trust`: names accept letters, digits, dot,
dash and underscore, with no spaces. Setup instructions appear directly beside each field;
they do not require loading a separate help page. Invalid field values are reported before
you save.

Only Jenkins administrators can change destination profiles. Pipeline authors choose a
profile name, rather than supplying a URL or a different credential. Account overrides
remain subject to the Trust token's account and access permissions.

## 8. Run a first-build check

Create a non-empty development secret in a group allowed by the Trust principal. Use a
Pipeline job whose URL matches the configured subject rule. Replace `test-secret-id` with
that secret's ID and run:

```groovy
pipeline {
    agent any
    stages {
        stage('Check Trust access') {
            steps {
                withCertLockerSecrets(server: 'production', secrets: [
                    [secretId: 'test-secret-id', variable: 'CHECK_SECRET']
                ]) {
                    sh '''
                        set +x
                        test -n "$CHECK_SECRET"
                        printf '%s\n' 'Trust binding succeeded'
                    '''
                }
            }
        }
    }
}
```

The build should print **Trust binding succeeded**. It does not need to print the secret
or temporary Trust token. On Windows agents, replace the shell check with an equivalent
`bat` or `powershell` step that checks the variable without displaying it.

After this succeeds, add the required credentials and files using the [usage recipes](usage.md)
or [complete example Jenkinsfile](../examples/Jenkinsfile).

## 9. Generate Pipeline syntax in Jenkins

Open a Pipeline job's **Pipeline Syntax → Snippet Generator**. Select
**withCertLockerSecrets: Bind Trust secrets as masked variables or private files**.
Choose a server, add secret bindings, set each variable and choose ENV or FILE mode.
Use `field: 'key'` for the key material inside a Trust-generated PEM/private-key secret.
Generate the snippet and place your build commands inside its block.

For direct Trust API access instead of automatic secret retrieval, select **withCertLockerOIDC**.
Its `TRUST_API_TOKEN` variable is a short-lived Trust access token; it is different from a
deployment token stored as a Trust secret.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| CertLocker section or Pipeline step is missing | Plugin enabled, dependencies installed, Jenkins restarted if requested |
| Unknown CertLocker server | Jenkinsfile profile name exactly matches a saved server name |
| OIDC credential missing or inaccessible | Correct credential ID, OpenID Connect string kind, Global scope and job/folder visibility |
| Cannot create a build identity | Jenkins URL, issuer, audience and provider claim templates; avoid unresolved claim variables |
| OIDC exchange denied | Principal active, HTTPS issuer exact match, audience match, correct full job subject and permitted token type |
| Exchange or fetch reports a TLS/connectivity failure | Controller DNS/network access and JVM CA trust; use the final HTTPS Gateway URL |
| Trust cannot fetch signing keys | Issuer reachable from Trust, correct `/jwks` URL, CA trusted, no proxy sign-in page |
| Secret fetch HTTP 400/403/404 | Correct account and secret ID, active secret, allowed groups and permissions |
| Secret fetch HTTP 401 | Token expiry or interactive authentication requirement; use a non-interactive workload principal |
| Redirect refused | Configure the final HTTPS URL, including the correct Gateway context path |
| Missing account | Set the profile's default account or the Pipeline's `account` option |
| Field missing/null/not scalar | Use `username`, `password`, `key` or a valid nested JSON pointer for the stored payload |
| Binary/large value cannot be an ENV binding | Use `mode: 'FILE'`; select `base64: true` only for a Base64-encoded source |
| FILE binding requires a node/agent | Place it inside `node { ... }` or a Declarative stage with an agent |

For cleanup, token lifetime, masking limits and file permissions, see [security and lifetime
behavior](usage.md#security-cleanup-and-lifetime).

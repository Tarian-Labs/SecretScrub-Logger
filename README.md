# SecretScrub Logger

SecretScrub Logger is a Burp Suite Professional extension that records completed, in-scope HTTP traffic as JSON Lines while removing likely credentials before anything is written to disk.

## Behaviour

- Records only traffic inside Burp's Target Scope.
- Skips common static assets such as images, fonts, JavaScript, CSS, maps, PDFs and archives.
- Redacts sensitive headers, cookies, URL parameters, JSON fields and form fields with `[REDACTED]`.
- Detects bearer tokens and JWT-shaped values even when their field name is not recognised.
- Limits each recorded request and response to 100 KB.
- Rotates numbered `.jsonl` files at 1 MB by default.
- Provides a **SecretScrub Logger** tab for choosing the output directory and starting a new file series.
- Lets testers add persisted, comma-separated custom sensitive field names for application-specific secrets.
- Persists the selected directory and filename prefix in Burp's extension settings.

Each line contains one transaction:

```json
{"t":"2026-08-30T12:00:00Z","method":"GET","url":"https://example.com/api/users","status":200,"request":"...","response":"..."}
```

## Requirements

- macOS
- JDK 21
- Burp Suite Professional with a compatible Montoya API

The Maven wrapper is included, so a separate Maven installation is not required.

## Build and test

```sh
./mvnw clean test
./mvnw package
```

The extension jar is written to `target/secretscrub-logger.jar`.

If Homebrew's JDK 21 is installed but your shell cannot find it, add this to `~/.zshrc`:

```sh
export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"
export JAVA_HOME="/opt/homebrew/opt/openjdk@21"
```

Then open a new terminal and verify it with `java -version` and `./mvnw -version`.

## Load in Burp

1. Build the jar with `./mvnw package`.
2. In Burp, open **Extensions → Installed → Add**.
3. Select **Java** and choose `target/secretscrub-logger.jar`.
4. Add the hosts you want recorded to Burp's Target Scope.
5. Use the **SecretScrub Logger** tab to select an output directory.

## Configuration

The output directory and filename prefix are configured in the extension tab. The initial directory can also be supplied with `-Dsecretscrublogger.dir=/path/to/logs`.

Change the 1 MB rotation threshold with `-Dsecretscrublogger.maxBytes=2097152`.

Raw HTTP traffic can contain highly sensitive data. Redaction is deliberately conservative, but generated logs should still be handled as security-sensitive material.

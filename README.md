# SecretScrub Logger

A Burp Suite Professional extension (Montoya API) that logs completed, in-scope HTTP
transactions as JSON Lines (JSONL), with secrets redacted and log files rotated at 1 MB.

## What it does

- Logs only requests that are inside Burp's **Target Scope**.
- Skips static assets: `.js .css .png .jpg .jpeg .gif .svg .ico .woff .woff2 .map .mp4 .pdf .zip`.
- Writes one JSON object per line to `C:\SecretScrubLogs\secretscrub-0001.jsonl`, `secretscrub-0002.jsonl`, ...
- Rotates to a new file once the current one reaches 1 MB.
- The output directory and file name prefix (`traffic` by default) are configurable at runtime
  from the extension's own **SecretScrub Logger** tab in Burp, with a **Start New File**
  button to begin a fresh numbered file immediately (e.g. to mark the start of a new
  investigation) instead of waiting for size-based rotation.
- Truncates `request` and `response` bodies at 100 KB, appending `[TRUNCATED]` when cut.
- Redacts secrets before they ever touch disk:
  - `Authorization: Bearer <token>` → `Authorization: Bearer TOKEN_0001`
  - Session/auth/JWT cookies (name contains `sess`, `auth`, or `jwt`) → `SESSION_0001`, `SESSION_0002`, ...
  - CSRF/XSRF tokens (headers, cookies, form fields, JSON fields) → `CSRF_0001`, `CSRF_0002`, ...
  - The same secret value always maps to the same identifier for the lifetime of the extension
    (tracked in-memory via `ConcurrentHashMap`, never persisted).

Each log line looks like:

```json
{"t":"2026-08-26T15:00:00Z","method":"GET","url":"https://example.com/api/users","status":200,"request":"...","response":"..."}
```

## Project layout

```
pom.xml
src/main/java/secretscrublogger/
  SecretScrubLoggerExtension.java - extension entry point
  TrafficLoggerHttpHandler.java- scope/asset filtering, orchestrates logging
  SecretRedactor.java          - token/cookie/CSRF redaction
  JsonlLogWriter.java          - rotating JSONL file writer
  TrafficJson.java             - minimal JSON serialization (no external dependency)
  TrafficLoggerConfig.java     - tunable constants
  LoggerSettingsPanel.java     - suite tab UI for the log directory/prefix and "Start New File"
```

## 1. Build it

Requires JDK 17+ and Maven.

```powershell
mvn clean package
```

This produces `target\secretscrub-logger.jar`. The Montoya API dependency is scoped as
`provided`, so it is not bundled into the jar — Burp supplies it at runtime.

## 2. Load it into Burp

1. Open Burp Suite Professional (2026.x).
2. Go to **Extensions → Installed → Add**.
3. Extension type: **Java**.
4. Extension file: select `target\secretscrub-logger.jar`.
5. Click **Next**, then **Close**. You should see `SecretScrub Logger loaded. Logging
  in-scope traffic to C:\SecretScrubLogs` in the extension's **Output** tab.

## 3. Verify logging is working

1. In **Target → Scope**, add a host you intend to test (e.g. `example.com`), and make sure
   "Use advanced scope control" reflects it.
2. Browse to that host through Burp's proxy (or send a request via Repeater to an in-scope URL).
3. Check `C:\SecretScrubLogs` for `secretscrub-0001.jsonl` and confirm it contains one JSON line per
   completed transaction.
4. Send requests to an out-of-scope host or to a `.js`/`.png` URL and confirm nothing new is
   appended — this validates the scope and asset filters.
5. Send a request with an `Authorization: Bearer ...` header or a session cookie and confirm the
   logged value is replaced with `TOKEN_000N` / `SESSION_000N`, not the raw secret.

### Configuration overrides

The log directory and file prefix are best changed from the **SecretScrub Logger** suite tab
(they're persisted automatically and take effect immediately, no restart needed). The rotation
size is still set via an optional Java system property, set via Burp's JVM args if needed:

- `-Dsecretscrublogger.maxBytes=524288` — change the rotation size in bytes (default `1048576`, 1 MB).

`-Dsecretscrublogger.dir=D:\OtherPath` also still works as the *initial* default directory the first
time the extension runs, before any value has been set from the suite tab.

## 4. Troubleshooting common Montoya API compilation errors

- **`package burp.api.montoya does not exist`** — the `montoya-api` dependency didn't resolve.
  Run `mvn -U clean package` to force Maven to re-check for the version, and confirm
  `net.portswigger.burp.extensions:montoya-api:2026.7` (or newer) exists on Maven Central for
  your Burp version. Update `<montoya.api.version>` in `pom.xml` to match the API version
  bundled with your Burp release if compilation fails on a specific class/method.
- **`class SecretScrubLoggerExtension is not abstract and does not override abstract method`** — a Montoya
  interface (e.g. `HttpHandler`) changed its method signatures between API versions. Check the
  method signatures in the version of `montoya-api` you depend on and update the overrides here
  to match.
- **`cannot find symbol: method isInScope(String)`** — some API versions expose scope checks via
  a different method/overload. Check `Scope` in the API you're targeting and adjust
  `TrafficLoggerHttpHandler.logIfApplicable`.
- **`NoClassDefFoundError` when loading the jar in Burp** — usually means a dependency was
  bundled with `compile` scope instead of `provided`, or an unrelated third-party jar wasn't
  shaded in. This project intentionally has zero runtime dependencies beyond the JDK and the
  Montoya API supplied by Burp, so this shouldn't occur unless the `pom.xml` scope was changed.
- **Extension loads but nothing is logged** — confirm the target host is actually in Burp's
  Target Scope (`api.scope().isInScope(url)` returns `false` silently by design) and that the
  path doesn't end in one of the ignored static-asset extensions.

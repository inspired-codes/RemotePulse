# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

RemotePulse is a zero-trust remote PowerShell administration system. A mobile PWA (the App) sends signed, encrypted commands through a blind-relay Hub to a Worker service running on the target machine.

## Commands

```bash
dotnet build RemotePulse.slnx
dotnet test RemotePulse.slnx                       # full suite; must be green before any commit

# Tests run on Microsoft.Testing.Platform + xUnit v3 (see global.json), so filters use MTP syntax:
dotnet test --project tests/inspired.codes.RemotePulse.Worker.Tests
dotnet test --project tests/inspired.codes.RemotePulse.Worker.Tests --filter-class "InspiredCodes.RemotePulse.Worker.Tests.FileLoggerProviderTests"
dotnet test --project tests/inspired.codes.RemotePulse.Worker.Tests --filter-method "*ClearLogFile_TruncatesLogAndRemovesRotatedFile"

# EF Core migrations (dotnet-ef is a local tool, pinned in .config/dotnet-tools.json)
dotnet tool restore
dotnet ef migrations add <Name> --project src/Applications/inspired.codes.RemotePulse.HubServer

# Package Worker release zips + .sha256 sidecars into dist/ and App wwwroot/downloads/
pwsh ./deploy/Package-WorkerRelease.ps1

# Check the cache/type/redirect rules of a running web container
bash scripts/verify-web.sh <base-url>
```

There is no separate lint step.

Tests need no database or installed service. The Hub integration tests host the real Hub through `WebApplicationFactory<Program>`, each with its own InMemory database. The EndToEnd tests (`RemotePulseFixture`) wire a real Hub, a real Worker and the real PowerShell engine into one process. Only the transport is in-memory, and the Worker's data directory and Local UI port are redirected to a temp folder and an ephemeral port, so a run never collides with an installed Worker. `WorkerSelfUpdateScriptTests` skips itself when run elevated, because elevated it would schedule a real update.

## Architecture

Three applications, three shared libraries:

- **HubServer**: ASP.NET Core minimal API with EF Core over PostgreSQL. Nearly every route lives in one file, `Program.cs` (a `MapGroup` split is planned). Migrations are applied at startup. If `ConnectionStrings:DefaultConnection` starts with `InMemory`, the Hub uses the EF InMemory provider instead, which is how the tests run. The Hub only ever stores ciphertext and verifies signed headers. It must never handle plaintext scripts or results.
  - `/ops` is the operator dashboard, gated by `ADMIN_TOKEN`. It's meant to be reachable only through an SSH tunnel to the Hub's loopback port; the edge proxy answers it with 404, and it's exempt from rate limiting.
  - Rate limiting is per client IP, in the Hub (`RateLimiting:*`): `/api/*` 10 r/s with a burst of 20, the support report 2/min with a burst of 3, pairing 10/min. The Hub trusts `X-Forwarded-For` from its immediate peer, so it must never publish a public port of its own.
- **Worker**: a .NET background service (Windows Service or systemd).
  - `PollingWorker` long-polls `GET /api/commands/poll?wait=N`. On the Hub side, `CommandNotifier` parks the request until work arrives.
  - `LocalUiServer` is a loopback-only Kestrel site on `http://localhost:7923/`. It serves the pairing QR, a status page and a log tail. Every mutating route checks `IsTrustedLocalOrigin` for CSRF protection.
  - `FileLoggerProvider` writes `worker.log`. `AppPaths` decides where on-disk state lives per OS.
  - The Worker key, `client_key.dat`, is protected only by file permissions: POSIX `0600`, or on Windows an NTFS ACL without inheritance for SYSTEM. On Windows, the installer also grants local Administrators when it re-secures an existing key.
  - `ExecutedCommandStore` persists the command envelopes already run, so a replay is rejected even across restarts and even if the Hub is malicious.
- **App**: Blazor WebAssembly PWA, served as static files by the `web` container: a small Caddy (`App/Caddyfile`, listens on 8080, non-root, read-only root fs, serves the Blazor `.br`/`.gz` assets as published) behind an edge Caddy. Crypto goes through the browser's WebCrypto API via JS interop. Keys are kept in IndexedDB.
  - The public landing page `wwwroot/portal.html`, the Security page `wwwroot/security.html` and the Worker bootstrap script `wwwroot/get-worker.ps1` are static files in the same wwwroot. They deploy together with the App.
- **Shared.Cryptography**: ECDSA P-256 signing plus `HybridCrypto` (ephemeral ECDH P-256 → HKDF-SHA256 → AES-256-GCM), and `PairingCrypto` for pairing v2. One keypair per endpoint is deliberately used for both signing and ECDH.
  - The command envelope carries a per-command 256-bit `ReplyKey`. The Worker encrypts results with it (AES-256-GCM, with `CommandId` as the AAD), so results are as opaque to the Hub as scripts are.
- **Shared.Contracts**: wire DTOs and enums, including `ExecutionMode`.
- **Client.PowerShellEngine**: runs scripts in an isolated runspace. `ExecutionMode` selects the security context:
  - `RunAsCurrentUser` impersonates the interactive user but stays in Session 0, so it cannot show UI.
  - `RunInteractiveAsCurrentUser` uses `CreateProcessAsUser` into `winsta0\default`. It is the only mode that can show UI.
  - `RunWithHighestLocalPrivileges` runs as SYSTEM or root. Privileges such as `SeShutdownPrivilege` must be explicitly enabled on the token with `AdjustTokenPrivileges`. Holding the privilege is not enough.

Every authenticated request carries the `X-Client-Id`/`X-App-Id`, `X-Timestamp`, `X-Nonce` and `X-Signature` headers. The signature covers `METHOD:path:id:timestamp:nonce`. Nonces are recorded in `SeenNonces` only after the signature verifies, and the clock-skew limit is 5 minutes. Workers also send `X-Worker-Version` and `X-Worker-Capabilities`. Those two headers aren't signed and are informational only: a Worker must fail closed on anything it can't handle and never trust the list. Each app's version is the `<Version>` in its `.csproj`, and Hub health (`GET /api/pairing/status/health`) reports that value.

Pairing is co-presence QR only, protocol v2 (`docs/specs/pairing-v2-key-binding-spec.md`). The QR link `/pairing/v2#k=<S>&fp=<fp>&ts=…` carries the secret `S` and the Worker key's SHA-256 fingerprint in the URL fragment. The Hub never sees `S`: both sides POST only `pid = HKDF(S, "…/id")` to `/api/pairing/v2`, and the Hub matches them by `pid`. The App rejects a Worker key that doesn't match `fp`. The Worker accepts the announced App key only with a valid `AppBindTag`, an HMAC under a key derived from `S` over `pid`, `fp`, `AppId` and the App key. Both screens show a 6-digit safety code (SAS). So the Hub can't substitute keys during pairing; the remaining trust is in whoever can see the QR.

Deeper docs: `docs/architecture.md` (code layout), `docs/communication.md` (topology, wire format, endpoint catalog, message flows), `docs/specs/`.

## Gotchas

- Workers install and update through the hosted one-liner `irm https://<host>/get-worker.ps1 | iex`, which calls `distribution/Installer.ps1`. Re-running the one-liner is the update path, and it preserves `MachineId`, keys and config.
- The App's **Update Worker** button sends the embedded `App/Scripts/Update-RemotePulseWorker.ps1` as SYSTEM/root. The script hands off to a one-shot OS job that re-runs `Installer.ps1`. If you change the installer's prompts or paths, update that script too. Never send a bare `irm …/get-worker.ps1 | iex` as a command: it runs inside the Worker process, and the installer's service stop kills it.
- In the Worker's hosted runspace, any native command that exits non-zero marks the whole result `Success: False`, even with `2>$null`. Predefined scripts must use only exit-0 calls on the happy path. For example, use `systemctl show -p ActiveState --value <unit>`, not `systemctl is-active`.
- The Worker zips that the servers offer come from the GitHub Release (`release.yml`, attested), not from a local `Package-WorkerRelease.ps1` run. The annotated tag's subject line becomes the announcement `message` in `worker-version.json`. `portal.html` shows the zip hashes from `worker-version.json` and has no hardcoded fallback.

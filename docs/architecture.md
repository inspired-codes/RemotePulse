# RemotePulse — Code Architecture

RemotePulse is a zero-trust remote administration system: an App
dispatches signed, encrypted PowerShell commands through a blind-relay Hub
to a Worker. This document describes how the code is
organized. For how the pieces talk to each other over the network, see
[communication.md](communication.md).

---

## 1. Solution Layout

```
RemotePulse.slnx
├── src/
│   ├── Applications/
│   │   ├── inspired.codes.RemotePulse.App/        (Blazor WASM PWA)
│   │   ├── inspired.codes.RemotePulse.Worker/ (cross-platform background service)
│   │   └── inspired.codes.RemotePulse.HubServer/                (Hub API)
│   └── Shared/
│       ├── inspired.codes.Client.PowerShellEngine/            (script execution)
│       ├── inspired.codes.RemotePulse.Shared.Contracts/       (shared wire enums)
│       └── inspired.codes.RemotePulse.Shared.Cryptography/    (keys, crypto)
├── tests/
│   ├── inspired.codes.Client.PowerShellEngine.Tests/
│   ├── inspired.codes.RemotePulse.App.Tests/
│   ├── inspired.codes.RemotePulse.Worker.Tests/
│   ├── inspired.codes.RemotePulse.HubServer.IntegrationTests/
│   ├── inspired.codes.RemotePulse.EndToEnd.Tests/     (full round trip, in-process)
│   └── inspired.codes.RemotePulse.Shared.Cryptography.Tests/
├── container/
│   └── docker-compose.yml
└── docs/
```

Platform: .NET 10, C# 14. Database: PostgreSQL via EF Core 10 / Npgsql
(with an `InMemory` fallback for dev/tests). Reverse proxy: Caddy in front of the Hub and the static App.

---

## 2. `Shared.Cryptography`

Provides the identity and encryption primitives every other project depends
on. Nothing in this project talks to the network.

- **`IKeyPairManager` / `KeyPairManager`** — owns an ECDSA P-256 keypair
  (used for signing) and derives a matching ECDiffieHellman P-256 keypair
  from the same curve parameters (used for encryption). The private key is
  written to disk as plain PKCS#8, protected only by owner-only file
  permissions (an NTFS ACL granting the service account alone on Windows,
  mode `0600` on Linux/macOS; the Windows installer additionally grants
  local Administrators when it re-secures an existing key). The permissions are applied before any key
  bytes are written. DPAPI was dropped because it has no cross-platform
  equivalent, so there is no at-rest encryption of the key bytes.
  Exposes `SignData`/`VerifyData` (ECDSA, SHA-256, IEEE P1363 signature
  format) and `HybridDecryptData`/`GetPublicKeyBase64`.
- **`HybridCrypto`** — static encrypt/decrypt pair implementing the wire
  format described in [communication.md](communication.md): an ephemeral
  ECDH P-256 key + AES-256-GCM, with the AES key derived via
  HKDF-SHA256. This is what lets a sender encrypt an arbitrary-length
  payload using only the recipient's *public* key.
- **`OnboardingTokenGenerator`** — builds the JSON blob
  (`{PublicKey, MachineId, ServerUrl}`) that gets rendered into the pairing
  QR code and (separately, and currently incorrectly — a known,
  test-invisible bug) reused as the body of the auto-registration retry.

## 3. `Client.PowerShellEngine`

Runs scripts locally on the Windows machine and reports back structured
results.

- **`PowerShellEngine`** — creates an isolated `Runspace` per invocation,
  executes the script, and captures every stream (output, error, warning,
  information, verbose, debug) into a `PowerShellResult`. Supports a
  timeout that force-stops the pipeline. Takes an `ExecutionMode`
  (`Shared.Contracts`) describing which Windows security context to run
  under: `RunAsCurrentUser` impersonates the active interactive user's
  thread token (no UI capability — still runs inside the Worker's own
  Session-0 process); `RunInteractiveAsCurrentUser` launches a new process
  inside the active session via `CreateProcessAsUser` (attached to
  `winsta0\default`) so UI (e.g. a toast) can render — output/error text is
  captured through a JSON result file written by a wrapper script rather
  than piped, since handle inheritance across `CreateProcessAsUser` into a
  different session is unreliable, so only `Output`/`Error`/`CombinedOutput`
  are populated for this mode (the per-stream Warning/Information/Verbose/
  Debug collections stay empty); `RunWithHighestLocalPrivileges` runs
  directly as the Worker's own identity (typically `NT AUTHORITY\SYSTEM`),
  no impersonation. Impersonation is enforced via `ImpersonationHelper`; if
  the host is running as SYSTEM and no interactive session is available for
  a mode that needs one, the request is rejected as a security-boundary
  violation rather than silently running as SYSTEM.

## 4. `Worker`

The background service that runs on the target machine (Windows, Linux, or
macOS).

- **`Program.cs`** — dual entry point. With no arguments (or
  `--run-as-service`), it boots as a Windows Service host, wiring up
  `KeyPairManager`, `PowerShellEngine`, and `PollingWorker` through DI. With
  a CLI flag it instead runs one-shot admin actions: `--install`/
  `--uninstall`/`--start`/`--stop` (wrap `sc.exe`), `--configure`
  (interactive `appsettings.json` wizard), `--register` (generates/loads
  keys, prompts for an enrollment token, and POSTs to
  `/api/clients/register`).
- **`PollingWorker`** (`BackgroundService`) — the daemon's heartbeat. By default
  it **long-polls**: `LongPollWaitSeconds` (25s) asks the Hub to hold each poll
  open until work arrives, so a queued command starts running within about a
  second instead of waiting out an interval, while *reducing* request volume.
  The request itself paces the loop, so no timer is involved; a failed cycle
  backs off 5s. Setting `LongPollWaitSeconds` to 0 falls back to a
  `PeriodicTimer` on `PollIntervalSeconds` (12s in `appsettings.json`, 5s in
  `appsettings.Development.json`). Either way it: signs and sends a
  poll request; if the response is a co-presence pairing announcement, saves
  the pairing to `pairing.json`; if it's a command,
  decrypts the script envelope, verifies its signature against every
  locally-known paired App public key, executes it via `PowerShellEngine`, and
  POSTs the result back. A 401 response triggers an (currently broken)
  auto re-registration attempt. Every signed request
  also carries an `X-Poll-Interval` header so the Hub can scale its liveness
  threshold to this machine's actual cadence (see §5). While long-polling that
  header reports the *wait window*, not the poll interval — a request parked for
  25s produces no new `LastSeenUtc` for those 25s, so reporting the shorter
  interval would make a perfectly healthy parked Worker grade amber for most of
  every cycle.
- **`CommandNotifier`** (Hub) — an in-memory per-machine signal that wakes a
  parked poll the instant a command is queued, rather than leaving it to the
  next re-check. Single-instance only by design; parked polls also re-check the
  database every 3s, which keeps a missed or cross-instance signal a latency
  cost rather than a correctness one.
- **`LocalUiServer`** — a self-hosted Kestrel instance on
  `http://localhost:7923`, started only while there are no local pairings.
  Serves a single HTML page with the pairing QR code and a small admin form
  to change `ServerUrl` (CSRF-guarded by Origin/Referer check). Shuts itself
  down 5 minutes after start, or immediately once a pairing
  completes.

## 5. `HubServer` (Hub)

ASP.NET Core minimal API, stateless except for what it persists in Postgres.
Acts as a blind relay: it authenticates *requests*, but never sees plaintext
script content (that's encrypted end-to-end between the App and the
Worker). See [communication.md](communication.md) for the full endpoint
catalog and message flows. (The `Client` entity below is the database's
name for a registered Worker machine — a naming leftover from before this
rename, not touched here since it's an actual EF Core class name.)

- **`Program.cs`** — all endpoints are defined inline as top-level
  `app.MapGet`/`app.MapPost` lambdas, plus two local helper functions,
  `VerifyClientRequestAsync` and `VerifyAppRequestAsync`, that both do the
  same three checks (timestamp within 5 minutes, nonce not seen before,
  ECDSA signature valid) against either a registered `Client` or a locked
  `Pairing`. `PruneExpiredDataService` (a `BackgroundService`) prunes expired
  nonces, expired co-presence tickets, and week-old command results every
  5 minutes.
- **Liveness watchdog** — `VerifyClientRequestAsync` is the single chokepoint
  every authenticated Worker request passes through, so it stamps
  `Client.LastSeenUtc` there (only *after* the signature verifies, so liveness
  can't be forged) and records the machine's self-reported
  `PollIntervalSeconds`. `GET /api/clients/status` then serves that back to the
  App as `{MachineId, LastSeenUtc, SecondsSinceLastSeen, IsOnline}` for every
  machine the calling App is paired with. Health is graded by how many expected
  check-ins the machine has missed, counted in units of *its own* reported
  cadence (so a 5s dev box and a slow-polling production machine are judged on
  the same footing): none missed is `Online`, one or two is `Degraded`, three
  or more — or never having checked in — is `Offline`. A jitter grace of
  `max(5s, interval/2)` is subtracted first, since a poll due at exactly T
  routinely lands a little after it and would otherwise flicker amber every
  cycle. At the shipped 12s cadence that puts amber at ~18s and red at ~42s.
  `SecondsSinceLastSeen`, `Health` and `MissedPolls` are all computed Hub-side
  because the App runs on a phone whose clock may be skewed.
- **`Data/RemotePulseContext.cs`** — the `DbContext` and every entity:
  `Client`, `Pairing`, `PendingCoPresence`, `ServerCommandEntity`,
  `CommandResultEntity`, `SeenNonce`, `SystemLogEntity`.

## 6. `App` (PWA)

Blazor WebAssembly app — the operator's console. Runs entirely client-side;
the "backend" it talks to is the Hub's public API.

- **`CryptoService`** — thin C# wrapper that calls into JS interop
  (`qrScannerInterop.*`) so all key generation, signing, and hybrid
  encryption happen through the browser's native WebCrypto API rather than
  `System.Security.Cryptography`. This is why the crypto stack is ECDSA/ECDH
  here too, matching the Windows Service side exactly.
- **`AppState`** — the app's in-memory + `IndexedDB`-backed state
  (`LocalStorageService`): the App's own identity/keypair, the list of
  paired Windows clients, command history, and a rolling console log. Also
  owns `IsMockMode`, a flag that makes `HubApiClient` fabricate entire
  command/result round-trips locally (with plausible canned
  PowerShell output) so the UI can be built and demoed without a live Hub
  Server or Worker.
- **`HubApiClient`** — the only class that makes real HTTP calls to the Hub:
  `SendCommandAsync` and the polling loop behind it (`PollCommandResultAsync`).
  `SendCommandAsync` takes a `recordInHistory` flag so diagnostics (the Test
  Connection button) don't push real commands out of the history dropdown.
- **`ClientWatchdog`** — polls `GET /api/clients/status` every 10s and keeps
  `AppState.ClientStatuses` fresh, so the UI can show whether each paired
  machine is actually reachable instead of just whether a pairing record
  exists locally. The cadence is deliberately close to the Worker's own 12s:
  `Degraded` spans only a couple of missed check-ins, so polling much slower
  would skip straight from green to red and the amber warning would never be
  seen. Paired clients are grouped by `ServerUrl` and queried one batch request
  per distinct Hub. It surfaces four states the old static "Paired & Locked"
  badge conflated: online (green), degraded (amber — missed a check-in or two),
  offline (red), and *hub unreachable* (grey — the App itself has no
  connectivity, so the client's state is simply unknown; neutral rather than
  red, since that's the phone's problem, not the client PC's). Transitions are
  logged to the console panel; steady state is not, or a 10s poll would flood
  the 200-line log. `ClientStatusDisplay` owns the state → colour/wording
  mapping and is unit tested directly.

## 7. Tests

Most test projects target exactly one of the above, by name:
`Shared.Cryptography.Tests` covers `KeyPairManager`/`HybridCrypto`;
`Client.PowerShellEngine.Tests` covers script execution; `Worker.Tests`
covers the Windows Service project; `App.Tests` covers `ClientWatchdog` and
`ClientStatusDisplay` (JS interop is faked, so no browser or bUnit is needed);
`HubServer.IntegrationTests` spins up the Hub API in-memory (via
`WebApplicationFactory`-style hosting) and drives it through `HttpClient`,
seeding `EnrollmentTokenEntity` rows directly into the DB rather than
exercising the client's own registration code path (which is how the
auto-registration bug stayed invisible to `dotnet test`).

`EndToEnd.Tests` is the exception — it deliberately spans everything. Its
`RemotePulseFixture` runs a real Hub, a real `PollingWorker`, and the real
`PowerShellEngine` in one process, wired together by an `IHttpClientFactory`
whose clients point at the in-memory Hub. Only the transport is substituted:
signing, hybrid encryption, signature verification, and script execution are
the genuine implementations, so a queued command really is decrypted,
verified, and executed by PowerShell. This covers the round trip that
previously had to be checked by hand against an installed service.

**Test isolation.** Both the Worker's data directory and `LocalUiServer`'s
port are injectable (`dataDirectory`, `localUiPort`; the latter accepts 0 for
an ephemeral port, read back via `LocalUiServer.Port`). This exists for a
concrete reason: these tests used to read and write the real
`C:\ProgramData\RemotePulse\pairing.json` and bind the real port 7923, so they
mutated live installation state and — whenever the Worker service was actually
running — silently queried *it* instead of the instance under test, then failed
on its unrelated config. Nothing in the suite may touch machine-wide state or a
fixed port.

What still isn't automated: the interactive-desktop half of
`RunInteractiveAsCurrentUser`. `CreateProcessAsUser` needs
`SeAssignPrimaryTokenPrivilege` (i.e. SYSTEM) plus a logged-in session, so it
can't run in an ordinary test process. It's automatable from a SYSTEM-context
runner, just not from a normal `dotnet test`.

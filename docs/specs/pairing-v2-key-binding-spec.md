# Spec: Pairing v2 — Bind Both Public Keys to the QR Secret

**Status:** implemented in Hub, App and Worker **2.0.0** (November 2026).
**Ships as:** one breaking release: Hub, App and Worker all at 2.0.0. The Hub carries one migration (column renames plus a nullable column). **v2 replaces v1 everywhere.** There is no backward compatibility: every PC is re-paired after the upgrade.

---

## 1. Why

Before v2 (this section describes v1 as it was), pairing trusted the Hub at the moment of pairing (TOFU):
- The QR secret `S` travels in the link fragment, but both sides then send it to the Hub. The Worker posts it (`LocalUiServer.cs:473-480`), and the App posts it (`HubApiClient.cs:52`).
- The Hub stores it (`Pairing.CoPresenceSecret`, `Program.cs:569,581`) and echoes it back to the Worker in the announcement `PAIRING:<AppId>:<AppPublicKey>:<S>` (`Program.cs:799-800`).
- The App learns the Worker's public key **only** from the Hub's `matched` response (`Program.cs:585`).
- The Worker accepts the App's key if the echoed `S` is one it generated recently (`PollingWorker.cs:381-390`). The Hub knows `S`, so that check proves nothing against the Hub.

**Result:** a Hub that is compromised *while you pair* can give the App its own "Worker" key and give the Worker its own "App" key. It then reads every script and can run its own. Nobody would notice. After pairing, the Hub can no longer inject a key, because the Worker requires a fresh `S` from its local UI.

## 2. Goals and non-goals

**Goals**
1. **The Hub never learns `S`.** It matches the two submissions on a value derived from `S`.
2. **The App verifies the Worker's key** independently of the Hub, using a fingerprint in the QR.
3. **The Worker verifies the App's key** independently of the Hub, using a tag only a holder of `S` can compute.
4. **One pairing protocol.** v1 is removed from the Hub, the App and the Worker. An old component **fails closed**: it never falls back, and an old App never sends `S` anywhere.
5. **Existing pairings** keep running commands, because the command path is unchanged, until each PC is re-paired (§5).

**Non-goals**
- **The same host serves the App and the Worker downloads.** A compromised server host can ship a malicious App or Worker. That's a separate track: signed releases, release hashes published elsewhere, and SRI or a separate origin for the App.
- **Someone who sees the QR within its 90 seconds** knows `S`, so cryptography can't stop them racing the real App. The safety code (§4.7) makes that race visible, and the 1:1 lock makes the real App fail loudly.
- **Backward compatibility** with Workers ≤ 1.2 or Apps ≤ 1.5 for pairing.

## 3. Threat model

| Attacker | v1 (removed) | v2 |
|---|---|---|
| Network MITM | Blocked: TLS, plus the App's proof-of-possession (SEC-6) | Unchanged |
| Hub compromised **during** pairing | Swaps both keys, invisibly | **Blocked.** The Hub never sees `S`. The App checks the Worker fingerprint from the QR, and the Worker checks the App's tag |
| Hub compromised **after** pairing | Blocked: needs a fresh `S` from the Worker's local UI | Unchanged |
| Someone who sees the QR within 90 s | Can race and pair their own App | Same race. The safety code shows it, and the real App gets a 409 |
| Stale cached App given a v2 link | n/a | Fails closed: it parses nothing and sends nothing (§4.2) |
| Compromised host serving a malicious App or Worker | Full compromise | Unchanged (non-goal) |

## 4. Design

All derivations live in one pure C# class, **`PairingCrypto`** in `Shared.Cryptography`, used by the Worker, the App and the tests. `SHA256`, `HMACSHA256` and `HKDF` carry no `[UnsupportedOSPlatform("browser")]` in net10.0, and the App already references `Shared.Cryptography` (checked by argon). Step 1 confirms this at runtime in the browser (§7). ECDSA signing stays in the existing WebCrypto JavaScript, because the App's private key lives there.

### 4.1 Values

`B64U` is base64url without padding. `S` is generated as today: 32 CSPRNG bytes, `B64U`, 43 characters (`LocalUiServer.cs:459`). Its UTF-8 string bytes are the input key material, so neither side has a decode step to disagree on.

| Name | Definition | Who computes it | Sent to the Hub? |
|---|---|---|---|
| `pid` | `B64U(HKDF-SHA256(ikm = UTF8(S), salt = empty, info = "RemotePulse/pairing/v2/id", L = 32))` | Worker, App | **Yes**: the match key (`PairingId`) |
| `bindKey` | `HKDF-SHA256(ikm = UTF8(S), salt = empty, info = "RemotePulse/pairing/v2/bind", L = 32)` | Worker, App | Never |
| `fp` | `B64U(SHA-256(WorkerSPKI))`, over the DER bytes of the Worker's public key | Worker (into the QR), App (to check) | No; it's in the QR fragment |
| `AppBindTag` | `B64U(HMAC-SHA256(bindKey, UTF8("RemotePulse/pairing/v2/app-bind:" + pid + ":" + fp + ":" + AppId + ":" + AppPublicKey)))` | App (creates), Worker (verifies) | Yes, relayed opaquely |
| `SAS` | first 4 bytes of `SHA-256(UTF8("RemotePulse/pairing/v2/sas:" + WorkerPublicKey + ":" + AppPublicKey))` as a big-endian uint32, `mod 1_000_000`, shown as `123 456` | Worker, App | Never |

None of `pid`, `fp`, `AppId`, `AppPublicKey` (standard base64) or `AppBindTag` contain `:`, so the joined strings are unambiguous. The tag includes `fp`, so it binds the App's key to the exact Worker key the App verified.

### 4.2 QR link v2

```
https://<hub>/pairing/v2#k=<S>&fp=<fp>&ts=<generatedAt, ISO 8601 UTC, URL-escaped>
```

Both the **path** (`/pairing/v2`) and the **secret's field name** (`k`, not `secret`) change, deliberately. The field rename is the protection that counts:
- An old App's in-app scanner hands any fragment to `/pairing/v1` whatever the link's path (`Scan.razor:88`).
- Its parser then finds no `secret` and stops, so `S` never leaves the phone.

Removing `/api/pairing/v1` on the Hub isn't enough on its own. A request body still reaches the server even when the answer is 404, and a malicious Hub would log it. `ts` stays only for the App's local staleness check, as today; it isn't part of any MAC.

### 4.3 Flow

```
[Worker] generates S, computes pid, fp; keeps (S, pid, expiry) in its ring
[Worker] --POST /api/pairing/v2 {PairingId: pid, Role: Client, MachineId, PublicKey}--> [Hub]
[Worker] LocalUiServer shows QR: https://<hub>/pairing/v2#k=S&fp=fp&ts=...
[App]    scans, computes pid, bindKey; signs UTF8(pid) (SEC-6 PoP); computes AppBindTag
[App]    --POST /api/pairing/v2 {PairingId: pid, Role: App, AppId, AppPublicKey,
                                 SecretSignature, AppBindTag}--> [Hub]
[Hub]    matches on pid, verifies PoP (unchanged), stores AppBindTag, returns {clientPublicKey}
[App]    checks B64U(SHA-256(clientPublicKey)) == fp; on mismatch: abort locally, don't save, warn
[Worker] --GET /api/commands/poll--> [Hub] --"PAIRING:<AppId>:<AppPublicKey>:<pid>:<AppBindTag>"-->
[Worker] finds S by pid (unexpired), recomputes AppBindTag with its own fp, FixedTimeEquals;
         accepts and saves only on a match
[Both]   show SAS
```

### 4.4 Hub (2.0.0)

- **Endpoint:** `POST /api/pairing/v2` replaces `/api/pairing/v1`, which is **removed**. Old Workers and stale Apps get 404 and stop. The rate-limit policy (`PairingRateLimit`) moves with it.
- **Contract:** in `CoPresenceSubmission`, `Secret` is renamed to `PairingId`, because the Hub never holds a secret again. `AppBindTag` is new and **required** for Role=App; it must be 43 base64url characters, or the Hub returns 400.
- **Proof of possession (SEC-6):** the logic is unchanged. The Hub verifies the App's signature over `UTF8(PairingId)`.
- **Storage:** one migration, `PairingV2`.
  - It renames `PendingCoPresences.Secret` to `PairingId` and `Pairings.CoPresenceSecret` to `PairingId`, and adds a nullable `AppBindTag` to both.
  - No data is deleted. Existing `Pairings` rows keep their old (expired, unusable) v1 secret until re-pairing overwrites it.
  - Update the doc comments: "`PairingId` = HKDF-derived match key, never the secret".
- **`FinalizeCoPresenceAsync`** (`Program.cs:564-583`): set `Pairing.AppBindTag = row.AppBindTag` in **both** branches.
  - The insert branch is the normal re-pair path: **Unpair** releases the pairing, and the Hub deletes the row (`Program.cs:716-723`).
  - The update branch (same `AppId`) covers re-pairing when that release never reached the Hub.
- **Announcement:** always the 5-part `PAIRING:<AppId>:<AppPublicKey>:<pid>:<AppBindTag>`. The 3-part code is removed.
- **No other logic.** The Hub can't verify the tag, and that's the point.

### 4.5 App (2.0.0)

- **Routing:**
  - `Pairing.razor` serves `/pairing/v2`, and reads the link from `location.hash` (`Pairing.razor:121`).
  - It keeps `/pairing/v1` only to tell the user: *"This PC runs an old RemotePulse Worker. Update it with the install command, then pair again."* That route sends nothing.
  - `PairingLinkParser` returns a `Version`: 2 for `k` + `fp`, and 1 for `secret`. Version 1 is recognised only to show the update message. A fragment with `k` but no `fp` is invalid.
  - The in-app scanner (`Scan.razor:88`, which hard-codes `/pairing/v1` today) navigates to `/pairing/v2` for Version 2, and shows the update message for Version 1.
- **Submission:** compute `pid`, sign it, compute `AppBindTag`, and POST to `/api/pairing/v2` as in §4.3. **`S` itself is never sent anywhere.** The v1 submission code is removed.
- **On `matched`:** compare the fingerprint first, and save the Worker only if it equals `fp`. On a mismatch, abort locally: don't save, send nothing further to the Hub, and show: *"The server returned a different key for this PC than its QR code. Pairing was stopped."*
  - The App can't clean up the Hub's side. `POST /api/pairing/release` accepts only Worker-signed requests (`Program.cs:702-713`), and a Hub that just swapped keys wouldn't honour it anyway.
  - Nothing dangerous is left behind. The Hub can't give the Worker a forged App key, because it can't compute a valid tag. If the Worker accepted the genuine App key, the user removes that pairing with **Unpair** on the PC page, which calls the Worker-signed release (`PollingWorker.cs:179,975`).
- **After success:** show the SAS and tell the user to compare it with the PC's screen.

### 4.6 Worker (2.0.0)

- **Links:** generate v2 links only. The ring holds `(S, pid, expiry)`, and the Hub submission carries `PairingId = pid`, never `S`.
- **Announcements:** accept **only the 5-part form**:
  1. Look up an unexpired `S` by `pid`.
  2. Recompute `AppBindTag` with its own `fp`.
  3. Compare with `CryptographicOperations.FixedTimeEquals`.
  4. Reject, and log at Error, on an unknown or expired `pid`, a tag mismatch or any other part count. **The 3-part v1 handling is removed**: the ring holds `S`, and the old form would let anyone who knows `S` pair through it.
- **Local page:** show the SAS of the paired App. `LocalPairing` in `pairing.json` already stores `AppPublicKey` (`PollingWorker.cs:962`), so `LocalUiServer` only needs it, or the precomputed SAS, alongside the `AppId`.

### 4.7 Safety code (SAS)

- **Where it shows:** on the Worker's paired page and on the App after pairing.
- **It's display-only**, with no confirm step.
- **What it catches:** the one remaining attack, someone who saw the QR and raced the real App. Against the Hub, §4.1–4.6 are already enough.

## 5. No backward compatibility

**Every mismatch fails closed:**

| Combination | Result |
|---|---|
| Worker ≤ 1.2 with the new Hub | Its `POST /api/pairing/v1` gets 404, and its pairing page shows the error. Update the Worker, then pair |
| Worker ≤ 1.2 link scanned by the new App | The App shows *"update the Worker"* and sends nothing |
| Stale cached App with a v2 link | It parses nothing (no `secret` field) and sends nothing. Reload the App |
| Worker 2.0 with the old Hub | `/api/pairing/v2` gets 404, so pairing fails. Deploy the Hub first |

**Existing pairings:** the command path is unchanged, so they keep running commands until they're re-paired. This includes the App's **Update Worker** button, which can deliver Worker 2.0.0.

**Re-pairing a PC** after the upgrade:
1. Update the Worker, either with the one-liner or with Update Worker.
2. Use **Unpair** on the PC page; the QR only appears once the PC is unpaired.
3. Scan the new QR, and compare the SAS on both screens.

No manual Hub cleanup is needed:
- **Unpair** releases the pairing with a Worker-signed request, and the Hub deletes that row. Re-pairing then takes the insert branch.
- If the Hub was unreachable during Unpair, the same phone (same `AppId`) re-pairs through the update branch.

The rollout itself deletes nothing. Each PC's old pairing is removed only by the user's own Unpair.

**Deploy order:** the Hub and the App first (Hub health then reports `2.0.0`, read from the `.csproj` `<Version>`), then the Worker 2.0.0 downloads, then re-pair each PC.

## 6. Tests

The existing v1 pairing tests are rewritten for v2. That covers `CoPresencePairingTests`, the Worker's PAIRING tests, the App's pairing tests and the E2E fixture's pairing setup.

| Project | Cases |
|---|---|
| `Shared.Cryptography.Tests` | Known-answer vectors for `pid`, `bindKey` → `AppBindTag`, `fp` and `SAS`. The tag changes if any single input changes |
| `HubServer.IntegrationTests` | v2 submissions match on `PairingId`. `AppBindTag` is stored in both `FinalizeCoPresenceAsync` branches, and the 5-part announcement is sent. An App submission without a valid `AppBindTag` gets 400. `/api/pairing/v1` gets 404 |
| `Worker.Tests` | A valid 5-part announcement is accepted. Rejected: wrong tag; unknown or expired `pid`; a tag computed for another `fp`; any 3-part form. The captured Hub request body never contains `S` |
| `App.Tests` | Parser returns `Version` 1 or 2, and `k` without `fp` is invalid. A v1 link shows the update message and sends nothing. The scanner routes v2 to `/pairing/v2`. A fingerprint mismatch means no save, an error shown, and no further Hub request. The submission never contains `S` |
| `EndToEnd.Tests` | v2 round trip, plus two malicious-Hub cases. If the Hub swaps `clientPublicKey` in the `matched` response, the App aborts. If it swaps `AppPublicKey` in the `Pairings` row, the Worker rejects |

## 7. Decisions

1. **SAS:** display-only, with no "codes match" confirm step.
2. **Fingerprint:** the full 256-bit `fp`; the link stays under about 200 characters.
3. **No backward compatibility:** v1 is removed everywhere, and every PC is re-paired.
4. **Worker version:** **2.0.0**, a breaking release.
5. **Hub and App versions:** both go to **2.0.0** too, so all three parts mark the same breaking release.

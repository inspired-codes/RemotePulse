using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using InspiredCodes.RemotePulse.App.Models;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;

namespace InspiredCodes.RemotePulse.App.Services;

public class HubApiClient
{
    private static readonly JsonSerializerOptions CommandJsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly HttpClient _http;
    private readonly AppState _appState;
    private readonly CryptoService _crypto;
    private readonly HashSet<string> _activePolledCommandIds = new();

    /// <summary>
    /// The verified Worker SPKI public key returned by the most recent successful
    /// <see cref="SubmitCoPresenceAsync"/> call, or <c>null</c> when the last call did not pair.
    /// </summary>
    public string? LastPairedClientPublicKey { get; private set; }

    public HubApiClient(HttpClient http, AppState appState, CryptoService crypto)
    {
        _http = http;
        _appState = appState;
        _crypto = crypto;
    }

    /// <summary>
    /// Submits this device's side of a Pairing v2 key-bound pairing
    /// (see docs/specs/pairing-v2-key-binding-spec.md §4.3).
    /// Derives <c>pid</c> and <c>AppBindTag</c> locally from <paramref name="secret"/> so the
    /// raw secret <c>S</c> is never sent to the Hub, and verifies the returned
    /// <c>clientPublicKey</c> against <paramref name="workerFingerprint"/> before saving.
    /// </summary>
    /// <param name="hubOrigin">The Hub's scheme://host:port, extracted from the scanned link. Falls back to the currently configured ServerUrl if not available.</param>
    public async Task<Models.PairingSubmitResult> SubmitCoPresenceAsync(
        string? hubOrigin,
        string secret,
        string workerFingerprint,
        DateTimeOffset generatedAtUtc)
    {
        LastPairedClientPublicKey = null;

        if (string.IsNullOrWhiteSpace(secret) || !PairingCrypto.IsValidBase64Url256(workerFingerprint))
        {
            _appState.Log("Invalid pairing link parameters (missing secret or invalid Worker fingerprint).");
            return Models.PairingSubmitResult.Failed;
        }

        string hubBaseUrl = (string.IsNullOrWhiteSpace(hubOrigin) ? _appState.ServerUrl : hubOrigin).TrimEnd('/');

        if (string.IsNullOrEmpty(_appState.AppId) || string.IsNullOrEmpty(_appState.AppPublicKeyBase64))
        {
            _appState.Log("Generating App keys before pairing...");
            await _appState.GenerateNewAppKeysAsync();
        }

        string pairingId = PairingCrypto.DerivePairingId(secret);
        string appBindTag = PairingCrypto.ComputeAppBindTag(
            secret,
            pairingId,
            workerFingerprint,
            _appState.AppId,
            _appState.AppPublicKeyBase64);

        _appState.Log("Signing derived pairing ID for proof-of-possession...");
        string secretSignature = await _crypto.SignBoundPayloadAsync(pairingId);

        _appState.Log($"Submitting Pairing v2 request to {hubBaseUrl}...");

        var submission = new CoPresenceSubmission(
            PairingId: pairingId,
            Role: "App",
            GeneratedAtUtc: generatedAtUtc,
            AppId: _appState.AppId,
            AppPublicKey: _appState.AppPublicKeyBase64,
            SecretSignature: secretSignature,
            AppBindTag: appBindTag
        );

        HttpResponseMessage response;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{hubBaseUrl}/api/pairing/v2")
            {
                Content = JsonContent.Create(submission)
            };
            request.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);
            response = await _http.SendAsync(request);
        }
        catch (Exception ex)
        {
            _appState.Log($"Failed to reach Hub: {ex.Message}");
            return Models.PairingSubmitResult.Failed;
        }

        if (!response.IsSuccessStatusCode)
        {
            string errText = await response.Content.ReadAsStringAsync();
            _appState.Log($"Pairing failed: {(int)response.StatusCode} - {errText}");
            return Models.PairingSubmitResult.Failed;
        }

        var result = await response.Content.ReadFromJsonAsync<CoPresenceMatchResult>();
        if (result == null || string.IsNullOrWhiteSpace(result.MachineId) || string.IsNullOrWhiteSpace(result.ClientPublicKey))
        {
            _appState.Log("Pairing response was missing expected fields.");
            return Models.PairingSubmitResult.Failed;
        }

        if (!PairingCrypto.VerifyPublicKeyFingerprint(result.ClientPublicKey, workerFingerprint))
        {
            _appState.Log("The server returned a different key for this PC than its QR code. Pairing was stopped.");
            return Models.PairingSubmitResult.FingerprintMismatch;
        }

        var client = new Models.PairedClient
        {
            MachineId = result.MachineId,
            PublicKey = result.ClientPublicKey,
            ServerUrl = hubBaseUrl,
            Alias = $"Client-{result.MachineId[^4..]}"
        };
        // The Hub has already matched and locked this pairing by this point, and the Worker will
        // learn of it independently on its own next poll - so this is always accepted, even over
        // the free-tier limit (see Models.AddClientResult). Rejecting here would just orphan a
        // pairing that's already real on both Hub and Worker.
        Models.AddClientResult addResult = await _appState.AddPairedClientAsync(client);
        LastPairedClientPublicKey = result.ClientPublicKey;
        _appState.ServerUrl = hubBaseUrl;
        _appState.Log($"Paired successfully with machine {result.MachineId}.");
        return addResult == Models.AddClientResult.AddedOverLimit
            ? Models.PairingSubmitResult.PairedOverLimit
            : Models.PairingSubmitResult.Paired;
    }

    private sealed class CoPresenceMatchResult
    {
        public string? Status { get; set; }
        public string? MachineId { get; set; }
        public string? ClientPublicKey { get; set; }
        public string? AppId { get; set; }
    }

    /// <summary>
    /// Encrypts, signs, queues a script for a paired machine and polls for its result.
    /// </summary>
    /// <param name="recordInHistory">
    /// False for diagnostics like the connection test, so a throwaway probe doesn't push the
    /// operator's real commands out of the history dropdown.
    /// </param>
    public async Task SendCommandAsync(Models.PairedClient client, string scriptText, ExecutionMode executionMode, int? timeoutSeconds = null, bool recordInHistory = true)
    {
        if (string.IsNullOrWhiteSpace(scriptText))
        {
            _appState.Log("Error: Script text is empty.");
            return;
        }

        _appState.IsAwaitingCommandResult = true;
        _appState.NotifyStateChanged();
        try
        {
            string appIdTag = _appState.AppId.Length >= 6 ? _appState.AppId[..6].ToUpperInvariant() : _appState.AppId.ToUpperInvariant();
            string commandId = $"CMD-{appIdTag}-{Guid.NewGuid().ToString("N")[..8].ToUpperInvariant()}";
            if (recordInHistory)
            {
                await _appState.AddScriptToHistoryAsync(scriptText);
            }

            string targetLabel = string.IsNullOrEmpty(client.Alias) ? client.MachineId : client.Alias;
            string uploadName = AppState.UploadMachineName(client.MachineId);
            string modeLabel = executionMode switch
            {
                ExecutionMode.RunWithHighestLocalPrivileges => "SYSTEM/root",
                ExecutionMode.RunInteractiveAsCurrentUser => "Interactive user",
                _ => "Current user"
            };
            string timeoutLabel = timeoutSeconds.HasValue ? $"{timeoutSeconds.Value}s" : "default timeout";
            _appState.Log($"▶ {targetLabel} · {modeLabel} · {timeoutLabel}",
                          $"▶ {uploadName} · {modeLabel} · {timeoutLabel}");

            // SEC-1/SEC-4: IssuedAtUtc + Nonce bind this signature to one specific delivery - a
            // Hub that captures and replays the encrypted envelope verbatim, or that only ever
            // saw a script-only signature, can no longer get it to execute again or under a
            // different ExecutionMode/Timeout than what was actually signed.
            _appState.Log("Signing script payload with App ECDSA private key...");
            string issuedAtUtc = DateTime.UtcNow.ToString("o");
            string envelopeNonce = Guid.NewGuid().ToString("N");
            string payloadToSign = $"{commandId}:{(int)executionMode}:{timeoutSeconds ?? 0}:{issuedAtUtc}:{envelopeNonce}:{scriptText}";
            string signatureBase64 = await _crypto.SignBoundPayloadAsync(payloadToSign);

            // Generate per-command ReplyKey in WebCrypto and store in IndexedDB pendingCommands
            string replyKeyBase64 = await _crypto.GenerateReplyKeyAsync(commandId, client.MachineId, timeoutSeconds);

            var commandEnvelope = new
            {
                CommandId = commandId,
                ExecutionMode = executionMode,
                TimeoutSeconds = timeoutSeconds,
                IssuedAtUtc = issuedAtUtc,
                Nonce = envelopeNonce,
                Script = scriptText,
                Signature = signatureBase64,
                ReplyKey = replyKeyBase64
            };
            string commandJson = System.Text.Json.JsonSerializer.Serialize(commandEnvelope);

            _appState.Log("Encrypting payload with client public key (hybrid AES-GCM + ECDH)...");
            string encryptedScriptBase64 = await _crypto.HybridEncryptPayloadAsync(commandJson, client.PublicKey);

            string serverUrl = client.ServerUrl.TrimEnd('/');
            string timestamp = DateTime.UtcNow.ToString("o");
            string nonce = Guid.NewGuid().ToString("N");
            string headerSignature = await _crypto.SignHeaderMessageAsync("POST", "/api/commands/queue", _appState.AppId, timestamp, nonce);

            using var request = new HttpRequestMessage(HttpMethod.Post, $"{serverUrl}/api/commands/queue");
            request.Headers.Add("X-App-Id", _appState.AppId);
            request.Headers.Add("X-Timestamp", timestamp);
            request.Headers.Add("X-Nonce", nonce);
            request.Headers.Add("X-Signature", headerSignature);
            request.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);

            request.Content = JsonContent.Create(new QueueCommandRequest(
                MachineId: client.MachineId,
                EncryptedScript: encryptedScriptBase64,
                ExecutionMode: executionMode,
                CommandId: commandId,
                TimeoutSeconds: timeoutSeconds
            ), options: CommandJsonOptions);

            _appState.Log("Posting command to queue...");
            var response = await _http.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                _appState.Log($"Command [{commandId}] placed in queue successfully. Waiting for the Worker to pick it up...");
                await PollCommandResultAsync(serverUrl, commandId, timeoutSeconds ?? 90, client);
            }
            else
            {
                await _crypto.RemovePendingCommandAsync(commandId);
                string errText = await response.Content.ReadAsStringAsync();
                _appState.Log($"Failed to queue command: {(int)response.StatusCode} - {errText}");
                _ = PostTelemetryAsync(serverUrl, new TelemetryLogEntry
                {
                    Source = "App",
                    AppId = _appState.AppId,
                    LogLevel = "Error",
                    Category = "HubApiClient",
                    EventName = "CommandQueueFailed",
                    Message = $"Failed to queue command [{commandId}]: {(int)response.StatusCode} - {errText}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        commandId = commandId,
                        statusCode = (int)response.StatusCode,
                        error = errText
                    })
                });
            }
        }
        catch (Exception ex)
        {
            // Anything here (network failure, the Hub briefly unreachable, a timeout, a crypto
            // error) used to propagate straight up through the Razor component with no catch
            // anywhere in between, crashing the whole render tree and showing Blazor's generic
            // "unhandled error" banner instead of a normal, recoverable log line - the same
            // failure path every other error in this method already logs gracefully.
            _appState.Log($"Failed to send command: {ex.Message}");
        }
        finally
        {
            _appState.IsAwaitingCommandResult = false;
            _appState.NotifyStateChanged();
        }
    }

    /// <summary>
    /// Resumes polling for pending commands stored in IndexedDB across PWA reloads.
    /// </summary>
    public async Task ResumePendingCommandsAsync()
    {
        try
        {
            var pending = await _crypto.GetPendingCommandsAsync();
            if (pending == null || pending.Count == 0) return;

            foreach (var cmd in pending)
            {
                if (string.IsNullOrWhiteSpace(cmd.CommandId)) continue;

                DateTime sentAt = DateTime.UtcNow;
                if (!string.IsNullOrWhiteSpace(cmd.SentAtUtc) &&
                    DateTime.TryParse(cmd.SentAtUtc, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var parsed))
                {
                    sentAt = parsed.ToUniversalTime();
                }

                int graceTimeout = cmd.TimeoutSeconds + 30;
                TimeSpan elapsed = DateTime.UtcNow - sentAt;

                if (elapsed.TotalSeconds >= graceTimeout)
                {
                    _appState.Log($"Cleaning up expired pending command [{cmd.CommandId}] from storage ({elapsed.TotalSeconds:F0}s elapsed).");
                    await _crypto.RemovePendingCommandAsync(cmd.CommandId);
                    continue;
                }

                var client = _appState.PairedClients.FirstOrDefault(c => c.MachineId == cmd.MachineId) ?? _appState.ActiveClient;
                string? serverUrl = client?.ServerUrl ?? _appState.ServerUrl;
                if (string.IsNullOrWhiteSpace(serverUrl))
                {
                    continue;
                }

                int remainingSeconds = Math.Max(5, (int)(graceTimeout - elapsed.TotalSeconds));
                lock (_activePolledCommandIds)
                {
                    if (_activePolledCommandIds.Contains(cmd.CommandId))
                    {
                        continue;
                    }
                }
                _appState.Log($"Resuming background poll for pending command [{cmd.CommandId}] ({remainingSeconds}s remaining)...");

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await PollCommandResultAsync(serverUrl, cmd.CommandId, cmd.TimeoutSeconds, client);
                    }
                    catch (Exception ex)
                    {
                        _appState.Log($"Error while resuming poll for [{cmd.CommandId}]: {ex.Message}");
                    }
                });
            }
        }
        catch (Exception ex)
        {
            _appState.Log($"Failed to resume pending commands: {ex.Message}");
        }
    }

    /// <summary>
    /// Polls for a command's result with dynamic timeout and backoff.
    /// In Phase 1 E2EE, ciphertext is decrypted in WebCrypto via CryptoService.
    /// Plaintext execution results are strictly refused as unverified rejections.
    /// </summary>
    public virtual async Task PollCommandResultAsync(string serverUrl, string commandId, int timeoutSeconds = 90, PairedClient? client = null)
    {
        string targetLabel = client != null && !string.IsNullOrEmpty(client.Alias) ? client.Alias : (client?.MachineId ?? "Worker");
        string uploadName = client != null ? AppState.UploadMachineName(client.MachineId) : "Worker";

        lock (_activePolledCommandIds)
        {
            if (!_activePolledCommandIds.Add(commandId))
            {
                return;
            }
        }

        try
        {
            int maxWaitSeconds = timeoutSeconds + 30;
            int currentDelayMs = 1000;
            const int progressLogIntervalSeconds = 10;
            int lastProgressLogSecond = 0;
            bool loggedUnexpectedIssue = false;
            DateTime startTime = DateTime.UtcNow;

            while ((DateTime.UtcNow - startTime).TotalSeconds < maxWaitSeconds)
            {
                await Task.Delay(currentDelayMs);
                currentDelayMs = Math.Min(5000, currentDelayMs + 1000);

                int elapsedSeconds = (int)(DateTime.UtcNow - startTime).TotalSeconds;
                if (elapsedSeconds - lastProgressLogSecond >= progressLogIntervalSeconds)
                {
                    _appState.Log($"Still waiting for {targetLabel} to respond... ({elapsedSeconds}s elapsed)",
                                  $"Still waiting for {uploadName} to respond... ({elapsedSeconds}s elapsed)");
                    lastProgressLogSecond = elapsedSeconds;
                }

                try
                {
                    string timestamp = DateTime.UtcNow.ToString("o");
                    string nonce = Guid.NewGuid().ToString("N");
                    string signature = await _crypto.SignHeaderMessageAsync("GET", $"/api/commands/results/{commandId}", _appState.AppId, timestamp, nonce);

                    using var request = new HttpRequestMessage(HttpMethod.Get, $"{serverUrl}/api/commands/results/{commandId}");
                    request.Headers.Add("X-App-Id", _appState.AppId);
                    request.Headers.Add("X-Timestamp", timestamp);
                    request.Headers.Add("X-Nonce", nonce);
                    request.Headers.Add("X-Signature", signature);
                    request.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);

                    var response = await _http.SendAsync(request);
                    if (response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadFromJsonAsync<CommandResult>();
                        if (result != null)
                        {
                            // Case 1: Plaintext rejection envelope (Worker rejected before execution)
                            if (!result.IsEncrypted)
                            {
                                string sanitizedReason = result.RejectionReason switch
                                {
                                    "EnvelopeUnreadable" => "EnvelopeUnreadable",
                                    "SignatureInvalid" => "SignatureInvalid",
                                    "FreshnessExpired" => "FreshnessExpired",
                                    "ReplayDetected" => "ReplayDetected",
                                    "EnvelopeUnsupported" => "EnvelopeUnsupported",
                                    _ => "Unknown"
                                };

                                string explanation = sanitizedReason switch
                                {
                                    "EnvelopeUnsupported" => client != null
                                        ? $": The Worker on {targetLabel} is too old for this command. Use Update Worker."
                                        : ": This Worker is too old for this command. Please update the Worker.",
                                    _ => string.Empty
                                };

                                string uploadExplanation = sanitizedReason switch
                                {
                                    "EnvelopeUnsupported" => client != null
                                        ? $": The Worker on {uploadName} is too old for this command. Use Update Worker."
                                        : ": This Worker is too old for this command. Please update the Worker.",
                                    _ => string.Empty
                                };

                                _appState.Log($"⚠️ Command rejected by {targetLabel}: {sanitizedReason}{explanation} (Unverified)",
                                              $"⚠️ Command rejected by {uploadName}: {sanitizedReason}{uploadExplanation} (Unverified)");
                                await _crypto.RemovePendingCommandAsync(commandId);
                                return;
                            }

                        // Case 2: Encrypted result payload
                        if (string.IsNullOrEmpty(result.EncryptedPayload))
                        {
                            _appState.Log($"❌ Command [{commandId}] returned encrypted status with empty payload.");
                            await _crypto.RemovePendingCommandAsync(commandId);
                            return;
                        }

                        CommandResultPayload? innerPayload = null;
                        try
                        {
                            string decryptedJson = await _crypto.DecryptResultAsync(commandId, result.EncryptedPayload);
                            innerPayload = JsonSerializer.Deserialize<CommandResultPayload>(decryptedJson, CommandJsonOptions);
                        }
                        catch (Exception ex)
                        {
                            _appState.Log($"❌ Failed to decrypt result for command [{commandId}]: {ex.Message}");
                            await _crypto.RemovePendingCommandAsync(commandId);
                            return;
                        }

                        if (innerPayload == null)
                        {
                            _appState.Log($"❌ Decrypted result payload for command [{commandId}] was empty or invalid JSON.");
                            await _crypto.RemovePendingCommandAsync(commandId);
                            return;
                        }

                        // Display output - Success and DurationMs are strictly from innerPayload
                        _appState.Log($"\n=== {targetLabel} · Command [{commandId}] Result (Duration: {innerPayload.DurationMs:F0}ms) ===",
                                      $"\n=== {uploadName} · Command [{commandId}] Result (Duration: {innerPayload.DurationMs:F0}ms) ===");
                        if (innerPayload.Success)
                        {
                            _appState.LogResultContent("Success Output:", innerPayload.Output ?? innerPayload.CombinedOutput);
                        }
                        else
                        {
                            _appState.LogResultContent("Error Output:", innerPayload.Error ?? innerPayload.CombinedOutput);
                            // Telemetry sanitization: do not send decrypted error text to Hub
                            _ = PostTelemetryAsync(serverUrl, new TelemetryLogEntry
                            {
                                Source = "App",
                                AppId = _appState.AppId,
                                LogLevel = "Warning",
                                Category = "HubApiClient",
                                EventName = "CommandResultError",
                                Message = $"Command [{commandId}] returned error.",
                                DataJson = JsonSerializer.Serialize(new
                                {
                                    commandId = commandId,
                                    durationMs = innerPayload.DurationMs,
                                    hasError = true
                                })
                            });
                        }

                        if (innerPayload.Streams != null)
                        {
                            if (innerPayload.Streams.Warnings != null && innerPayload.Streams.Warnings.Count > 0)
                            {
                                _appState.LogResultContent($"Warnings ({innerPayload.Streams.Warnings.Count}):", string.Join("\n", innerPayload.Streams.Warnings.Select(w => $"  [WARN] {w}")));
                            }
                            if (innerPayload.Streams.Errors != null && innerPayload.Streams.Errors.Count > 0)
                            {
                                _appState.LogResultContent($"Error Stream ({innerPayload.Streams.Errors.Count}):", string.Join("\n", innerPayload.Streams.Errors.Select(e => $"  [ERR] {e}")));
                            }
                            if (innerPayload.Streams.Information != null && innerPayload.Streams.Information.Count > 0)
                            {
                                _appState.LogResultContent($"Information Stream ({innerPayload.Streams.Information.Count}):", string.Join("\n", innerPayload.Streams.Information.Select(info => $"  [INFO] {info}")));
                            }
                            if (innerPayload.Streams.Verbose != null && innerPayload.Streams.Verbose.Count > 0)
                            {
                                _appState.LogResultContent($"Verbose Stream ({innerPayload.Streams.Verbose.Count}):", string.Join("\n", innerPayload.Streams.Verbose.Select(v => $"  [VERBOSE] {v}")));
                            }
                            if (innerPayload.Streams.Debug != null && innerPayload.Streams.Debug.Count > 0)
                            {
                                _appState.LogResultContent($"Debug Stream ({innerPayload.Streams.Debug.Count}):", string.Join("\n", innerPayload.Streams.Debug.Select(d => $"  [DEBUG] {d}")));
                            }
                            if (!string.IsNullOrEmpty(innerPayload.Streams.ExceptionDetails))
                            {
                                _appState.LogResultContent("Exception Diagnostics:", innerPayload.Streams.ExceptionDetails);
                            }
                        }

                        await _crypto.RemovePendingCommandAsync(commandId);
                        return;
                    }

                    if (!loggedUnexpectedIssue)
                    {
                        _appState.Log($"Result check for [{commandId}] returned 200 but the body was empty or didn't parse.");
                        loggedUnexpectedIssue = true;
                    }
                }
                else if (response.StatusCode != System.Net.HttpStatusCode.NotFound && !loggedUnexpectedIssue)
                {
                    string body = await response.Content.ReadAsStringAsync();
                    _appState.Log($"Result check for [{commandId}] returned {(int)response.StatusCode}: {body}");
                    loggedUnexpectedIssue = true;
                }
            }
            catch (Exception ex)
            {
                if (!loggedUnexpectedIssue)
                {
                    _appState.Log($"Result check for [{commandId}] failed: {ex.Message}");
                    loggedUnexpectedIssue = true;
                }
            }
        }

        _appState.Log($"No response from {targetLabel} after {maxWaitSeconds}s (CommandId: {commandId}). Is it running and connected to the Hub?",
                      $"No response from {uploadName} after {maxWaitSeconds}s (CommandId: {commandId}). Is it running and connected to the Hub?");
        await _crypto.RemovePendingCommandAsync(commandId);
    }
    finally
    {
        lock (_activePolledCommandIds)
        {
            _activePolledCommandIds.Remove(commandId);
        }
    }
    }

    public async Task<bool> PostTelemetryAsync(string serverUrl, TelemetryLogEntry entry)
    {
        try
        {
            if (_appState.HubReachable == false || !_appState.DeviceOnline)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(_appState.AppId))
            {
                return false;
            }

            string timestamp = DateTime.UtcNow.ToString("o");
            string nonce = Guid.NewGuid().ToString("N");
            string signature = await _crypto.SignHeaderMessageAsync("POST", "/api/telemetry/logs", _appState.AppId, timestamp, nonce);

            string cleanUrl = serverUrl.TrimEnd('/');
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{cleanUrl}/api/telemetry/logs");
            request.Headers.Add("X-App-Id", _appState.AppId);
            request.Headers.Add("X-Timestamp", timestamp);
            request.Headers.Add("X-Nonce", nonce);
            request.Headers.Add("X-Signature", signature);
            request.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);

            request.Content = JsonContent.Create(new[] { entry });
            var response = await _http.SendAsync(request);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            // Non-fatal telemetry catch
            return false;
        }
    }
}

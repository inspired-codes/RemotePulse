using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using InspiredCodes.Client.PowerShellEngine;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;

using CommandPayload = InspiredCodes.RemotePulse.Shared.Contracts.ServerCommand;

namespace InspiredCodes.RemotePulse.Worker;

/// <summary>
/// Hosted worker running as a Windows Service.
/// Periodically queries the Hub Server for commands, validates signature wrappers,
/// decrypts payloads, and dispatches them to the local PowerShell execution engine.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="PollingWorker"/> class.
/// </remarks>
public sealed class PollingWorker(
    ILogger<PollingWorker> logger,
    IHttpClientFactory httpClientFactory,
    IKeyPairManager keyManager,
    IPowerShellEngine psEngine,
    string machineId,
    int pollIntervalSeconds,
    ILogger<LocalUiServer> localUiLogger,
    string serverUrl,
    string? dataDirectory = null,
    int localUiPort = LocalUiServer.DefaultPort,
    int longPollWaitSeconds = 0,
    LocalUiServer? localUiServer = null) : BackgroundService
{
    private readonly ILogger<PollingWorker> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    private readonly IKeyPairManager _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
    private readonly IPowerShellEngine _psEngine = psEngine ?? throw new ArgumentNullException(nameof(psEngine));

    private record LocalPairing(string AppId, string AppPublicKey);

    private readonly ILogger<LocalUiServer> _localUiLogger = localUiLogger ?? throw new ArgumentNullException(nameof(localUiLogger));

    private static readonly JsonSerializerOptions CommandPayloadJsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    public static readonly string WorkerVersion =
        typeof(PollingWorker).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? typeof(PollingWorker).Assembly.GetName().Version?.ToString(3)
        ?? "1.2.0";

    public static readonly string WorkerCapabilities = string.Empty;

    private LocalUiServer? _localUiServer = localUiServer;

    private bool IsLongPolling => longPollWaitSeconds > 0;

    /// <summary>
    /// How often the Hub can expect to hear from us, which is what its liveness grading keys off.
    /// When long-polling that is the wait window rather than the poll interval, since a parked
    /// request produces no heartbeat until it returns.
    /// </summary>
    private int EffectiveHeartbeatSeconds => IsLongPolling ? longPollWaitSeconds : pollIntervalSeconds;

    /// <summary>
    /// Floor on how long one idle long-poll cycle may take before the next one starts. The Hub
    /// holding the request open normally paces the loop, so this only bites when that isn't
    /// happening - and then it degrades the Worker to exactly its configured fixed-poll cadence
    /// rather than to a tight retry loop.
    /// </summary>
    private TimeSpan MinimumIdleCycle => TimeSpan.FromSeconds(Math.Max(1, pollIntervalSeconds));

    /// <summary>
    /// Where pairing state lives. Defaults to the machine-wide data directory, but is
    /// overridable so tests can point at a temp folder instead of mutating (and fighting over)
    /// the installed service's live C:\ProgramData\RemotePulse\pairing.json.
    /// </summary>
    private string GetPairingFilePath()
    {
        return dataDirectory != null
            ? Path.Combine(dataDirectory, "pairing.json")
            : AppPaths.GetPairingFilePath();
    }

    private List<LocalPairing> LoadPairings()
    {
        string path = GetPairingFilePath();
        if (!File.Exists(path)) return new List<LocalPairing>();
        try
        {
            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<List<LocalPairing>>(json) ?? new List<LocalPairing>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "pairing.json at {Path} could not be parsed; treating as unpaired.", path);
            return new List<LocalPairing>();
        }
    }

    private void SavePairing(string appId, string appPublicKey)
    {
        string path = GetPairingFilePath();
        string? dir = Path.GetDirectoryName(path);
        if (dir != null && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        List<LocalPairing> pairings = LoadPairings();
        // Remove existing duplicate pairing if present, then insert updated profile
        pairings.RemoveAll(p => p.AppId == appId);
        pairings.Add(new LocalPairing(appId, appPublicKey));

        string json = JsonSerializer.Serialize(pairings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }

    private List<LocalPairing> RemovePairing(string appId)
    {
        string path = GetPairingFilePath();
        List<LocalPairing> pairings = LoadPairings();
        pairings.RemoveAll(p => p.AppId == appId);

        string json = JsonSerializer.Serialize(pairings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
        return pairings;
    }

    private string GetExecutedCommandsFilePath()
    {
        return dataDirectory != null
            ? Path.Combine(dataDirectory, "executed-commands.json")
            : AppPaths.GetExecutedCommandsFilePath();
    }

    private ExecutedCommandStore? _executedCommands;

    /// <summary>SEC-1 replay protection - see <see cref="ExecutedCommandStore"/>.</summary>
    private ExecutedCommandStore ExecutedCommands => _executedCommands ??= new ExecutedCommandStore(GetExecutedCommandsFilePath(), _logger);

    /// <summary>
    /// Overrides BackgroundService execution, starting the polling scheduler loop.
    /// </summary>
    /// <param name="stoppingToken">Service stopping cancellation token.</param>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (IsLongPolling)
        {
            _logger.LogInformation(
                "RemotePulse background poll service started. Long-polling with a {Wait}s wait window (commands are picked up as soon as they are queued).",
                longPollWaitSeconds);
        }
        else
        {
            _logger.LogInformation("RemotePulse background poll service started. Interval: {Interval} seconds.", pollIntervalSeconds);
        }

        // The Local UI always starts - either the onboarding QR flow (no pairings yet) or a
        // status page confirming which App IDs are already paired, so the operator never hits a
        // silent connection-refused at http://localhost:7923/ either way.
        IList<LocalPairing> pairings = LoadPairings();
        IReadOnlyList<string> pairedAppIds = pairings.Select(p => p.AppId).ToList();
        IReadOnlyDictionary<string, string> pairedAppPublicKeys = pairings.ToDictionary(p => p.AppId, p => p.AppPublicKey);
        _logger.LogInformation(
            pairedAppIds.Count == 0
                ? "No active pairings detected. Launching Local Onboarding Web Server on http://localhost:7923..."
                : "{Count} active pairing(s) detected. Launching Local Status Web Server on http://localhost:7923...",
            pairedAppIds.Count);
        if (_localUiServer == null)
        {
            _localUiServer = new LocalUiServer(_localUiLogger, _keyManager, _httpClientFactory, machineId, serverUrl, pairedAppIds,
                unpairAsync: async appId =>
                {
                    var remaining = RemovePairing(appId).Select(p => p.AppId).ToList();
                    await ReleasePairingOnHubAsync(appId).ConfigureAwait(false);
                    return remaining;
                },
                port: localUiPort,
                pairedAppPublicKeys: pairedAppPublicKeys);
            await _localUiServer.StartAsync().ConfigureAwait(false);
        }
        else
        {
            await _localUiServer.StartAsync().ConfigureAwait(false);
        }

        // First poll execution on startup
        try
        {
            await PollAndExecuteAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in startup poll execution.");
        }

        if (IsLongPolling)
        {
            // No timer: the Hub holds each request open until there is work or the window
            // expires, so the request itself paces the loop. Reconnecting immediately is what
            // gets a queued command running within a second or so instead of within an interval.
            while (!stoppingToken.IsCancellationRequested)
            {
                long startedAtTicks = Environment.TickCount64;
                bool handledWork;

                try
                {
                    handledWork = await PollAndExecuteAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    // Includes a proxy cutting the parked connection short: treated as an
                    // ordinary empty cycle, so an aggressive idle timeout degrades this into
                    // more frequent polling rather than breaking it.
                    _logger.LogWarning(ex, "Long-poll cycle failed; retrying after backoff.");
                    handledWork = false;
                }

                if (handledWork)
                {
                    // Reconnect at once: there may be more queued behind what we just ran, and
                    // making the operator wait a full window for the second of two commands is
                    // exactly the latency this feature exists to remove.
                    continue;
                }

                // An idle cycle is supposed to be paced by the Hub holding the request open for
                // the wait window. When it isn't - the Hub is down, or it's an older build that
                // ignores ?wait=, or a proxy answered instead - the cycle returns immediately and
                // nothing throws, so without a floor this loop would spin as fast as the network
                // allows: hammering a server that is already unhappy, filling worker.log, and
                // (against a live Hub) writing a replay-protection nonce row per request.
                TimeSpan elapsed = TimeSpan.FromMilliseconds(Environment.TickCount64 - startedAtTicks);
                TimeSpan remaining = MinimumIdleCycle - elapsed;
                if (remaining > TimeSpan.Zero)
                {
                    _logger.LogDebug(
                        "Idle poll cycle returned after {Elapsed:F1}s, short of the {Wait}s wait window - pacing the next one by {Remaining:F1}s.",
                        elapsed.TotalSeconds, longPollWaitSeconds, remaining.TotalSeconds);
                    try
                    {
                        await Task.Delay(remaining, stoppingToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }
        else
        {
            // Setup PeriodicTimer for non-blocking asynchronous waits
            using PeriodicTimer timer = new PeriodicTimer(TimeSpan.FromSeconds(pollIntervalSeconds));

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
                    {
                        await PollAndExecuteAsync(stoppingToken).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown sequence
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred during background polling cycle.");
                }
            }
        }

        _logger.LogInformation("RemotePulse background poll service stopped.");
        if (_localUiServer != null)
        {
            await _localUiServer.StopAsync().ConfigureAwait(false);
            _localUiServer.Dispose();
            _localUiServer = null;
        }
    }

    /// <summary>
    /// One poll cycle. Returns true when the cycle actually handled something - a command, or a
    /// pairing announcement - and false when it came back empty or failed.
    /// </summary>
    /// <remarks>
    /// The long-poll loop reconnects immediately, so it needs to tell a cycle that returned fast
    /// because there was work from one that returned fast because nothing is pacing it. See
    /// <see cref="ExecuteAsync"/>.
    /// </remarks>
    private async Task<bool> PollAndExecuteAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("Initiating poll request to server.");

        using HttpClient client = _httpClientFactory.CreateClient("RemotePulseHub");

        // 1. Prepare secure poll request with cryptographic authorization headers
        string pollUrl = longPollWaitSeconds > 0
            ? $"api/commands/poll?wait={longPollWaitSeconds.ToString(CultureInfo.InvariantCulture)}"
            : "api/commands/poll";

        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, pollUrl);
        AddSignatureHeaders(request);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to connect to RemotePulse Hub server: {Message}", ex.Message);
            return false;
        }

        if (response.StatusCode == HttpStatusCode.NoContent)
        {
            _logger.LogDebug("No commands available in queue.");
            return false;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            _logger.LogWarning("Server rejected authentication signature (401). This machine isn't paired with the Hub yet - open http://localhost:7923 and scan the QR code with the RemotePulse Mobile App.");
            return false;
        }

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Server returned unexpected status: {StatusCode}", response.StatusCode);
            return false;
        }

        // 2. Process command payload
        CommandPayload? command;
        try
        {
            command = await response.Content.ReadFromJsonAsync<CommandPayload>(CommandPayloadJsonOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse command payload from server.");
            return false;
        }

        if (command == null || string.IsNullOrWhiteSpace(command.Script))
        {
            _logger.LogWarning("Received empty command payload.");
            return false;
        }

        // 3. Check for Pairing Announcement (Pairing v2 key-bound flow)
        if (command.Script.StartsWith("PAIRING:"))
        {
            // Pairing v2 requires the 5-part announcement: PAIRING:<AppId>:<AppPublicKey>:<pid>:<AppBindTag>.
            // Any 3-part v1 form or other part count is rejected and logged at Error.
            string[] parts = command.Script.Substring(8).Split(':');
            if (parts.Length == 4 &&
                !string.IsNullOrWhiteSpace(parts[0]) &&
                !string.IsNullOrWhiteSpace(parts[1]) &&
                !string.IsNullOrWhiteSpace(parts[2]) &&
                !string.IsNullOrWhiteSpace(parts[3]))
            {
                string appId = parts[0];
                string appPublicKey = parts[1];
                string pairingId = parts[2];
                string appBindTag = parts[3];

                if (_localUiServer == null)
                {
                    _logger.LogError("PAIRING announcement rejected: Local UI server is not active (no secret ring available) for App Unique ID: {AppId}", appId);
                    return true;
                }

                if (!_localUiServer.TryGetValidSecret(pairingId, out string? secret))
                {
                    _logger.LogError("PAIRING announcement rejected: unknown or expired pairing ID for App Unique ID: {AppId}", appId);
                    return true;
                }

                string workerFingerprint = PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64());
                if (!PairingCrypto.VerifyAppBindTag(secret, pairingId, workerFingerprint, appId, appPublicKey, appBindTag))
                {
                    _logger.LogError("PAIRING announcement rejected: invalid AppBindTag for App Unique ID: {AppId}", appId);
                    return true;
                }

                // SEC-2: In this tier, each Worker is strictly 1:1 with Mobile.
                // Reject pairing announcements if already paired with a different Mobile device.
                // Re-pairing the same AppId (e.g. key rotation) remains allowed.
                List<LocalPairing> existingPairings = LoadPairings();
                if (existingPairings.Count > 0 && !existingPairings.Any(p => p.AppId == appId))
                {
                    _logger.LogError("PAIRING announcement rejected: Worker already paired with a different Mobile device (App Unique ID {ExistingAppId}); unpair it first before pairing {NewAppId}.", existingPairings[0].AppId, appId);
                    return true;
                }

                SavePairing(appId, appPublicKey);
                _logger.LogInformation("Pairing confirmed via co-presence for App Unique ID: {AppId}", appId);

                _logger.LogInformation("Pairing confirmed. Switching Local UI to the paired status page...");
                List<LocalPairing> updatedPairings = LoadPairings();
                IReadOnlyList<string> pairedAppIds = updatedPairings.Select(p => p.AppId).ToList();
                IReadOnlyDictionary<string, string> pairedAppPublicKeys = updatedPairings.ToDictionary(p => p.AppId, p => p.AppPublicKey);
                await _localUiServer.TransitionToPairedAsync(pairedAppIds, pairedAppPublicKeys).ConfigureAwait(false);
            }
            else
            {
                _logger.LogError("PAIRING announcement rejected: expected 5-part v2 announcement, received malformed payload ({PartCount} parts): {Script}", parts.Length + 1, command.Script);
            }
            return true;
        }

        // 4. Decrypt and verify normal script payload
        _logger.LogInformation("Command [{CommandId}] received. Decrypting script payload...", command.CommandId);
        if (!DecryptAndVerifyScript(command, out string decryptedScript, out string? replyKeyBase64, out string rejectionCode, out string decryptError))
        {
            _logger.LogError("Command [{CommandId}] validation rejected ({RejectionCode}): {Error}", command.CommandId, rejectionCode, decryptError);

            // Post rejection result with generic code
            await PostRejectionResultAsync(client, command.CommandId, rejectionCode, cancellationToken).ConfigureAwait(false);

            var validationTelemetry = new TelemetryLogEntry
            {
                Source = "Worker",
                MachineId = machineId,
                LogLevel = "Error",
                Category = "PollingWorker",
                EventName = "CommandValidationRejected",
                Message = $"Command [{command.CommandId}] validation rejected: {rejectionCode}",
                DataJson = JsonSerializer.Serialize(new
                {
                    commandId = command.CommandId,
                    executionMode = command.ExecutionMode.ToString(),
                    timeoutSeconds = command.TimeoutSeconds,
                    rejectionCode = rejectionCode
                })
            };
            await PostTelemetryAsync(client, validationTelemetry, cancellationToken).ConfigureAwait(false);
            return true;
        }

        _logger.LogInformation("Command [{CommandId}] successfully validated. Executing (ExecutionMode={ExecutionMode})...", command.CommandId, command.ExecutionMode);

        // 5. Execute script completely in-process
        PowerShellResult result;
        try
        {
            TimeSpan? timeout = command.TimeoutSeconds.HasValue ? TimeSpan.FromSeconds(command.TimeoutSeconds.Value) : null;
            result = await _psEngine.ExecuteScriptAsync(decryptedScript, command.ExecutionMode, timeout).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled crash during script execution wrapper.");
            result = new PowerShellResult
            {
                MachineId = machineId,
                Success = false,
                Error = $"Internal execution crash: {ex.Message}",
                CombinedOutput = $"[CRASH] {ex.Message}",
                Exception = ex
            };
        }

        _logger.LogInformation("Command [{CommandId}] executed. Success: {Success}. Posting results back...", command.CommandId, result.Success);

        var execTelemetry = new TelemetryLogEntry
        {
            Source = "Worker",
            MachineId = machineId,
            LogLevel = result.Success ? "Information" : "Warning",
            Category = "PowerShellEngine",
            EventName = "CommandExecuted",
            Message = result.Success
                ? $"Command [{command.CommandId}] executed successfully in {result.Duration.TotalMilliseconds:F0}ms."
                : $"Command [{command.CommandId}] failed in {result.Duration.TotalMilliseconds:F0}ms.",
            DataJson = JsonSerializer.Serialize(new
            {
                commandId = command.CommandId,
                executionMode = command.ExecutionMode.ToString(),
                durationMs = result.Duration.TotalMilliseconds,
                success = result.Success,
                hasError = !result.Success
            })
        };
        await PostTelemetryAsync(client, execTelemetry, cancellationToken).ConfigureAwait(false);

        // 6. Send execution feedback back to server
        try
        {
            await PostResultAsync(client, command.CommandId, result, replyKeyBase64, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to report command results back to server.");
        }

        return true;
    }

    private bool DecryptAndVerifyScript(CommandPayload command, out string scriptText, out string? replyKeyBase64, out string rejectionCode, out string error)
    {
        scriptText = string.Empty;
        replyKeyBase64 = null;
        rejectionCode = "EnvelopeUnreadable";
        error = string.Empty;

        // SEC-1: Reject undefined outer execution modes before decrypting or processing.
        if (!Enum.IsDefined(command.ExecutionMode))
        {
            rejectionCode = "EnvelopeUnreadable";
            error = $"Undefined outer ExecutionMode {(int)command.ExecutionMode}. Command rejected.";
            return false;
        }

        try
        {
            byte[] encryptedBytes;
            try
            {
                encryptedBytes = Convert.FromBase64String(command.Script);
            }
            catch
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Base64 decode failed for command script.";
                return false;
            }

            byte[] decryptedBytes;
            try
            {
                decryptedBytes = _keyManager.HybridDecryptData(encryptedBytes);
            }
            catch (Exception ex)
            {
                rejectionCode = "EnvelopeUnreadable";
                error = $"Failed to hybrid-decrypt script: {ex.Message}";
                return false;
            }

            string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);

            using var doc = JsonDocument.Parse(decryptedJson);

            // Envelope version gate:
            // - An envelope without 'v' is v1 (all of today's Apps).
            // - In Worker 1.2.0 (P0 Step 2), v2 parsing is not yet implemented (comes in Step 3),
            //   so explicit v: 2 and any other version number is rejected with EnvelopeUnsupported.
            // - An invalid/non-numeric 'v' property is rejected with EnvelopeUnreadable.
            if (doc.RootElement.TryGetProperty("v", out var vProp))
            {
                if (vProp.ValueKind != JsonValueKind.Number || !vProp.TryGetInt32(out int version))
                {
                    rejectionCode = "EnvelopeUnreadable";
                    error = "Invalid envelope version property 'v'. Command rejected.";
                    return false;
                }

                rejectionCode = "EnvelopeUnsupported";
                error = $"Envelope version {version} is not supported by this Worker.";
                return false;
            }

            if (!doc.RootElement.TryGetProperty("Script", out var scriptProp) ||
                !doc.RootElement.TryGetProperty("Signature", out var signatureProp))
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Invalid script payload envelope.";
                return false;
            }

            string script = scriptProp.GetString() ?? string.Empty;
            string signatureBase64 = signatureProp.GetString() ?? string.Empty;

            if (doc.RootElement.TryGetProperty("ReplyKey", out var replyKeyProp))
            {
                replyKeyBase64 = replyKeyProp.GetString();
            }

            if (string.IsNullOrWhiteSpace(replyKeyBase64))
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Signed envelope is missing ReplyKey. Command rejected.";
                return false;
            }

            try
            {
                byte[] keyBytes = Convert.FromBase64String(replyKeyBase64);
                if (keyBytes.Length != 32)
                {
                    rejectionCode = "EnvelopeUnreadable";
                    error = $"Invalid ReplyKey length: expected 32 bytes, got {keyBytes.Length}. Command rejected.";
                    return false;
                }
            }
            catch
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Invalid base64 in ReplyKey. Command rejected.";
                return false;
            }

            // SEC-1/SEC-4: ExecutionMode, IssuedAtUtc and Nonce are mandatory parts of the
            // signed envelope.
            if (!doc.RootElement.TryGetProperty("ExecutionMode", out var modeProp))
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Signed envelope is missing ExecutionMode. Command rejected.";
                return false;
            }
            ExecutionMode envelopeMode;
            if (modeProp.ValueKind == JsonValueKind.Number)
            {
                int modeInt = modeProp.GetInt32();
                if (!Enum.IsDefined((ExecutionMode)modeInt))
                {
                    rejectionCode = "EnvelopeUnreadable";
                    error = $"Undefined ExecutionMode numeric value {modeInt} specified in signed envelope.";
                    return false;
                }
                envelopeMode = (ExecutionMode)modeInt;
            }
            else if (Enum.TryParse<ExecutionMode>(modeProp.GetString(), ignoreCase: true, out var parsedMode) && Enum.IsDefined(parsedMode))
            {
                envelopeMode = parsedMode;
            }
            else
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Invalid ExecutionMode specified in signed envelope.";
                return false;
            }

            if (envelopeMode != command.ExecutionMode)
            {
                rejectionCode = "SignatureInvalid";
                error = $"ExecutionMode mismatch: outer payload requested '{command.ExecutionMode}', but signed envelope authorized '{envelopeMode}'. Command rejected.";
                return false;
            }

            if (!doc.RootElement.TryGetProperty("IssuedAtUtc", out var issuedAtProp) ||
                !DateTimeOffset.TryParse(issuedAtProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var issuedAtUtc))
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Signed envelope is missing or has an invalid IssuedAtUtc. Command rejected.";
                return false;
            }
            if (Math.Abs((DateTimeOffset.UtcNow - issuedAtUtc).TotalMinutes) > 5.0)
            {
                rejectionCode = "FreshnessExpired";
                error = "Signed envelope IssuedAtUtc is outside the 5-minute freshness window. Command rejected.";
                return false;
            }
            string issuedAtRaw = issuedAtProp.GetString()!;

            if (!doc.RootElement.TryGetProperty("Nonce", out var nonceProp) || string.IsNullOrWhiteSpace(nonceProp.GetString()))
            {
                rejectionCode = "EnvelopeUnreadable";
                error = "Signed envelope is missing Nonce. Command rejected.";
                return false;
            }
            string nonce = nonceProp.GetString()!;

            // SEC-1: Replay check
            if (ExecutedCommands.Contains(command.CommandId, nonce))
            {
                rejectionCode = "ReplayDetected";
                error = "Command envelope already executed (replay rejected).";
                return false;
            }

            // Verify script signature against paired App Public Key
            var pairings = LoadPairings();
            if (pairings.Count == 0)
            {
                rejectionCode = "SignatureInvalid";
                error = "Client is not paired with any app.";
                return false;
            }

            string boundMessage = $"{command.CommandId}:{(int)command.ExecutionMode}:{command.TimeoutSeconds ?? 0}:{issuedAtRaw}:{nonce}:{script}";
            byte[] boundBytes = Encoding.UTF8.GetBytes(boundMessage);
            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromBase64String(signatureBase64);
            }
            catch
            {
                rejectionCode = "SignatureInvalid";
                error = "Signature base64 unreadable.";
                return false;
            }

            bool signatureVerified = false;
            foreach (var pairing in pairings)
            {
                try
                {
                    using var ecdsa = ECDsa.Create();
                    ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pairing.AppPublicKey), out _);

                    if (ecdsa.VerifyData(boundBytes, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    {
                        signatureVerified = true;
                        break;
                    }
                }
                catch
                {
                    // Try next pairing key
                }
            }

            if (!signatureVerified)
            {
                rejectionCode = "SignatureInvalid";
                error = "Script signature verification failed against all paired apps. Command rejected.";
                return false;
            }

            ExecutedCommands.Record(command.CommandId, nonce);

            scriptText = script;
            rejectionCode = string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            rejectionCode = "EnvelopeUnreadable";
            error = $"Failed to decrypt script: {ex.Message}";
            return false;
        }
    }

    private async Task PostRejectionResultAsync(HttpClient client, string commandId, string rejectionCode, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "api/commands/results");
        AddSignatureHeaders(request);

        CommandResult rejectionResult = new CommandResult
        {
            CommandId = commandId,
            Success = false,
            DurationMs = 0,
            IsEncrypted = false,
            EncryptedPayload = null,
            RejectionReason = rejectionCode
        };

        request.Content = JsonContent.Create(rejectionResult);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            _logger.LogInformation("Rejection result for command [{CommandId}] successfully reported ({RejectionCode}).", commandId, rejectionCode);
        }
        else
        {
            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogWarning("Failed to post rejection result for command [{CommandId}]: {StatusCode} - {Body}", commandId, response.StatusCode, body);
        }
    }

    private static CommandResultPayload EnforceSizeCap(CommandResultPayload payload)
    {
        const int maxBytes = 7 * 1024 * 1024;
        const string marker = "\n[Output truncated by Worker at 7MB payload cap]";

        string json = JsonSerializer.Serialize(payload);
        if (Encoding.UTF8.GetByteCount(json) <= maxBytes)
        {
            return payload;
        }

        // 1. Truncate CombinedOutput first
        string combined = payload.CombinedOutput;
        if (combined.Length > 1000)
        {
            int excess = Encoding.UTF8.GetByteCount(json) - maxBytes;
            int keep = Math.Max(0, combined.Length - excess - 1024);
            combined = (keep > 0 ? combined[..keep] : string.Empty) + marker;
        }
        else
        {
            combined = marker;
        }

        var trimmed = payload with { CombinedOutput = combined };
        json = JsonSerializer.Serialize(trimmed);
        if (Encoding.UTF8.GetByteCount(json) <= maxBytes)
        {
            return trimmed;
        }

        // 2. Truncate Output next
        string output = payload.Output;
        int excessOutput = Encoding.UTF8.GetByteCount(json) - maxBytes;
        int keepOutput = Math.Max(0, output.Length - excessOutput - 2048);
        output = (keepOutput > 0 ? output[..keepOutput] : string.Empty) + marker;

        trimmed = trimmed with { Output = output };
        json = JsonSerializer.Serialize(trimmed);
        while (Encoding.UTF8.GetByteCount(json) > maxBytes && output.Length > marker.Length)
        {
            output = output[..Math.Max(0, output.Length - 100000)] + marker;
            trimmed = trimmed with { Output = output };
            json = JsonSerializer.Serialize(trimmed);
        }
        if (Encoding.UTF8.GetByteCount(json) <= maxBytes)
        {
            return trimmed;
        }

        // 3. Truncate Error next
        string error = payload.Error;
        if (!string.IsNullOrEmpty(error))
        {
            int excessError = Encoding.UTF8.GetByteCount(json) - maxBytes;
            int keepError = Math.Max(0, error.Length - excessError - 2048);
            error = (keepError > 0 ? error[..keepError] : string.Empty) + marker;

            trimmed = trimmed with { Error = error };
            json = JsonSerializer.Serialize(trimmed);
            while (Encoding.UTF8.GetByteCount(json) > maxBytes && error.Length > marker.Length)
            {
                error = error[..Math.Max(0, error.Length - 100000)] + marker;
                trimmed = trimmed with { Error = error };
                json = JsonSerializer.Serialize(trimmed);
            }
        }
        if (Encoding.UTF8.GetByteCount(json) <= maxBytes)
        {
            return trimmed;
        }

        // 4. Drop Streams as fallback if still exceeding cap
        if (trimmed.Streams != null)
        {
            trimmed = trimmed with
            {
                Streams = null,
                CombinedOutput = trimmed.CombinedOutput + "\n[Streams omitted by Worker at 7MB payload cap]"
            };
            json = JsonSerializer.Serialize(trimmed);
        }

        // Final safety guarantee
        while (Encoding.UTF8.GetByteCount(json) > maxBytes && (trimmed.Output.Length > marker.Length || trimmed.Error.Length > marker.Length))
        {
            trimmed = trimmed with
            {
                Output = trimmed.Output.Length > 2000 ? trimmed.Output[..2000] + marker : marker,
                Error = trimmed.Error.Length > 2000 ? trimmed.Error[..2000] + marker : marker,
                CombinedOutput = marker
            };
            json = JsonSerializer.Serialize(trimmed);
        }

        return trimmed;
    }

    private async Task PostResultAsync(HttpClient client, string commandId, PowerShellResult result, string? replyKeyBase64, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(replyKeyBase64))
        {
            _logger.LogError("Command [{CommandId}] executed but ReplyKey is missing. Posting rejection.", commandId);
            await PostRejectionResultAsync(client, commandId, "EnvelopeUnreadable", cancellationToken).ConfigureAwait(false);
            return;
        }

        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "api/commands/results");
        AddSignatureHeaders(request);

        static IReadOnlyList<string>? CapStream(IReadOnlyList<string>? lines, int maxLines = 100)
        {
            if (lines == null || lines.Count == 0) return null;
            if (lines.Count <= maxLines) return lines;
            var list = lines.Take(maxLines).ToList();
            list.Add($"... [Truncated: {lines.Count - maxLines} additional lines omitted]");
            return list;
        }

        string? exDetails = null;
        if (result.Exception != null)
        {
            string exStr = result.Exception.ToString();
            exDetails = exStr.Length > 4096 ? exStr[..4096] + "... [Truncated]" : exStr;
        }

        var streams = new CommandStreams(
            Warnings: CapStream(result.WarningLines),
            Errors: CapStream(result.ErrorLines),
            Information: CapStream(result.InformationLines),
            Verbose: CapStream(result.VerboseLines),
            Debug: CapStream(result.DebugLines),
            ExceptionDetails: exDetails
        );

        bool hasAnyStream = streams.Warnings != null ||
                            streams.Errors != null ||
                            streams.Information != null ||
                            streams.Verbose != null ||
                            streams.Debug != null ||
                            streams.ExceptionDetails != null;

        CommandResultPayload payload = new CommandResultPayload
        {
            Success = result.Success,
            DurationMs = result.Duration.TotalMilliseconds,
            Output = result.Output,
            Error = result.Error,
            CombinedOutput = result.CombinedOutput,
            Streams = hasAnyStream ? streams : null
        };

        // Enforce 7MB serialized JSON size cap
        payload = EnforceSizeCap(payload);
        string payloadJson = JsonSerializer.Serialize(payload);

        // Encrypt with AES-256-GCM using replyKeyBase64, AAD = commandId
        byte[] key = Convert.FromBase64String(replyKeyBase64);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(payloadJson);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[16];
        byte[] aad = Encoding.UTF8.GetBytes(commandId);

        using (var aesGcm = new AesGcm(key, 16))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag, aad);
        }

        byte[] encryptedBlob = new byte[12 + ciphertext.Length + 16];
        Buffer.BlockCopy(nonce, 0, encryptedBlob, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, encryptedBlob, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, encryptedBlob, 12 + ciphertext.Length, 16);

        string encryptedPayloadBase64 = Convert.ToBase64String(encryptedBlob);

        CommandResult commandResult = new CommandResult
        {
            CommandId = commandId,
            Success = result.Success,
            DurationMs = result.Duration.TotalMilliseconds,
            IsEncrypted = true,
            EncryptedPayload = encryptedPayloadBase64,
            RejectionReason = null
        };

        request.Content = JsonContent.Create(commandResult);

        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            _logger.LogInformation("Feedback for command [{CommandId}] successfully reported.", commandId);
        }
        else
        {
            _logger.LogError("Failed to submit command [{CommandId}] feedback. Server returned: {StatusCode}", commandId, response.StatusCode);
        }
    }

    private async Task ReleasePairingOnHubAsync(string appId)
    {
        try
        {
            using HttpClient client = _httpClientFactory.CreateClient("RemotePulseHub");
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "api/pairing/release");
            request.Content = JsonContent.Create(new ReleasePairingRequest(appId));
            AddSignatureHeaders(request);

            using HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Hub pairing release confirmed for AppId {AppId}", appId);
            }
            else
            {
                _logger.LogWarning("Hub pairing release returned status {StatusCode} for AppId {AppId}", response.StatusCode, appId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to notify Hub of pairing release for AppId {AppId}. Local unpairing succeeded.", appId);
        }
    }

    private void AddSignatureHeaders(HttpRequestMessage request)
    {
        RequestSigner.AddSignatureHeaders(request, _keyManager, machineId);
        request.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);
        request.Headers.TryAddWithoutValidation(ProtocolConstants.WorkerVersionHeaderName, WorkerVersion);
        request.Headers.TryAddWithoutValidation(ProtocolConstants.WorkerCapabilitiesHeaderName, WorkerCapabilities);

        // Lets the Hub scale its "is this machine still online?" threshold to how often we
        // actually check in, instead of assuming a default and marking a deliberately
        // slow-polling Worker as permanently dead.
        //
        // While long-polling, the effective heartbeat rate is the *wait window*, not the poll
        // interval: a request parked for 25s produces no new LastSeenUtc for those 25s. Reporting
        // the old 12s here would make a perfectly healthy parked Worker look like it had missed
        // two check-ins and grade amber for most of every cycle.
        request.Headers.Add("X-Poll-Interval", EffectiveHeartbeatSeconds.ToString(CultureInfo.InvariantCulture));
    }

    private async Task PostTelemetryAsync(HttpClient client, TelemetryLogEntry entry, CancellationToken cancellationToken)
    {
        try
        {
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "api/telemetry/logs");
            AddSignatureHeaders(request);
            request.Content = JsonContent.Create(new[] { entry });
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Telemetry log upload to Hub failed (non-fatal).");
        }
    }
}


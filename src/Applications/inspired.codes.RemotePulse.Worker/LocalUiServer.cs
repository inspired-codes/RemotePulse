using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.RemotePulse.Worker;

/// <summary>
/// A minimal, self-hosted Kestrel engine running quietly inside the service.
/// Serves the client onboarding QR page (a co-presence pairing link, see docs/specs/pairing-v2-key-binding-spec.md)
/// and shuts down once pairing confirms or upon a 5-minute timeout.
/// </summary>
public sealed class LocalUiServer : IDisposable
{
    /// <summary>The port the onboarding/status UI listens on in production.</summary>
    public const int DefaultPort = 7923;

    /// <summary>How long an on-demand co-presence pairing code is valid for (90 seconds).</summary>
    public static readonly TimeSpan PairingCodeValidity = TimeSpan.FromSeconds(90);

    private readonly ILogger<LocalUiServer> _logger;
    private readonly IKeyPairManager _keyManager;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _machineId;

    /// <summary>
    /// Not readonly - TransitionToPairedAsync reassigns this when a pairing completes while the
    /// onboarding UI is still up, and the "/" handler reads it fresh on every request (not a
    /// captured snapshot) so that change is reflected without needing to touch route
    /// registration or restart Kestrel.
    /// </summary>
    private IReadOnlyList<string> _pairedAppIds;
    private IReadOnlyDictionary<string, string> _pairedAppPublicKeys;
    private readonly Func<string, Task<IReadOnlyList<string>>> _unpairAsync;
    private string _serverUrl;
    private WebApplication? _app;
    private bool _isStarted;

    private readonly object _secretLock = new();
    private string _currentSecret = string.Empty;
    private DateTimeOffset _currentGeneratedAtUtc;
    private readonly List<(string Secret, string PairingId, DateTimeOffset ExpiresAt)> _recentSecrets = new();

    /// <summary>
    /// Looks up the active, unexpired co-presence secret <c>S</c> corresponding to the given
    /// HKDF-derived <paramref name="pairingId"/> (<c>pid</c>) (Pairing v2, §4.6).
    /// </summary>
    public bool TryGetValidSecret(string? pairingId, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? secret)
    {
        secret = null;
        if (string.IsNullOrWhiteSpace(pairingId)) return false;
        lock (_secretLock)
        {
            var now = DateTimeOffset.UtcNow;
            _recentSecrets.RemoveAll(s => s.ExpiresAt < now);
            var match = _recentSecrets.FirstOrDefault(s => string.Equals(s.PairingId, pairingId, StringComparison.Ordinal));
            if (string.IsNullOrEmpty(match.Secret))
            {
                return false;
            }
            secret = match.Secret;
            return true;
        }
    }

    /// <summary>
    /// Registers a secret into the valid co-presence secret ring (primarily for testing).
    /// </summary>
    public string RegisterSecretForTesting(string secret, TimeSpan? validity = null)
    {
        string pairingId = PairingCrypto.DerivePairingId(secret);
        lock (_secretLock)
        {
            _currentSecret = secret;
            _currentGeneratedAtUtc = DateTimeOffset.UtcNow;
            _recentSecrets.Add((secret, pairingId, DateTimeOffset.UtcNow.Add(validity ?? TimeSpan.FromMinutes(5))));
        }
        return pairingId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LocalUiServer"/> class.
    /// </summary>
    /// <param name="unpairAsync">
    /// Called when the status page's Unpair button is used, with the App ID to remove.
    /// Owns actually rewriting the pairing file (PollingWorker's storage, not this class's
    /// concern) and returns the resulting list of App IDs still paired afterward.
    /// </param>
    /// <param name="port">
    /// Listening port. Defaults to <see cref="DefaultPort"/>; pass 0 to bind an ephemeral port
    /// (read it back from <see cref="Port"/> after <see cref="StartAsync"/>), which is what tests
    /// use so they never collide with an installed Worker service already holding 7923.
    /// </param>
    public LocalUiServer(ILogger<LocalUiServer> logger, IKeyPairManager keyManager, IHttpClientFactory httpClientFactory, string machineId, string serverUrl, IReadOnlyList<string>? pairedAppIds = null, Func<string, Task<IReadOnlyList<string>>>? unpairAsync = null, int port = DefaultPort, IReadOnlyDictionary<string, string>? pairedAppPublicKeys = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _machineId = machineId;
        _serverUrl = string.IsNullOrWhiteSpace(serverUrl) ? "https://psrun.inspired.codes/" : serverUrl;
        _pairedAppIds = pairedAppIds ?? Array.Empty<string>();
        _pairedAppPublicKeys = pairedAppPublicKeys ?? new Dictionary<string, string>();
        _unpairAsync = unpairAsync ?? (_ => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>()));
        _port = port;
    }

    /// <summary>
    /// The port actually bound. Equals the configured port, or the OS-assigned one once
    /// <see cref="StartAsync"/> has completed when 0 was requested.
    /// </summary>
    public int Port => _port;

    private int _port;

    private string BaseUrl => $"http://localhost:{_port}";

    /// <summary>
    /// Starts the Kestrel server listening on localhost port 7923.
    /// </summary>
    public async Task StartAsync()
    {
        if (_isStarted) return;
        _isStarted = true;

        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.WebHost.ConfigureKestrel(options =>
        {
            // Kestrel rejects ListenLocalhost(0) - dynamic binding needs an explicit loopback
            // address - so the ephemeral case takes the IPAddress.Loopback path instead.
            if (_port == 0)
            {
                options.Listen(System.Net.IPAddress.Loopback, 0, listenOptions =>
                {
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2;
                });
            }
            else
            {
                options.ListenLocalhost(_port, listenOptions =>
                {
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2;
                });
            }
        });

        // Keep logging silent to avoid polluting console/service outputs
        builder.Logging.ClearProviders();

        _app = builder.Build();

        bool startedUnpaired = _pairedAppIds.Count == 0;

        _app.MapGet("/", async context =>
        {
            context.Response.ContentType = "text/html; charset=utf-8";

            // Checked fresh on every request (not a captured snapshot) so a pairing completing
            // mid-session - see TransitionToPairedAsync - is reflected on the very next load.
            var (activeUrl, remainingSecs) = GetActivePairingInfo();
            string html = _pairedAppIds.Count > 0
                ? GetStatusHtml(_pairedAppIds, _serverUrl)
                : GetOnboardingHtml(activeUrl, remainingSecs, _serverUrl);
            await context.Response.WriteAsync(html);
        });

        _app.MapPost("/api/config", async (HttpContext context) =>
        {
            // CSRF protection: only allow requests originating from our local UI
            if (!IsTrustedLocalOrigin(context))
            {
                var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? context.Request.Headers["Referer"].FirstOrDefault() ?? "unknown";
                _logger.LogWarning("Rejected /api/config request from untrusted origin: {Origin}", origin);
                return Results.StatusCode(403);
            }

            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
            string body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("serverUrl", out var urlProp))
            {
                string newUrl = urlProp.GetString()?.Trim() ?? string.Empty;
                bool force = doc.RootElement.TryGetProperty("force", out var forceProp) && forceProp.GetBoolean();

                if (!string.IsNullOrWhiteSpace(newUrl))
                {
                    if (!Uri.TryCreate(newUrl, UriKind.Absolute, out Uri? parsedUri) ||
                        (parsedUri.Scheme != Uri.UriSchemeHttp && parsedUri.Scheme != Uri.UriSchemeHttps) ||
                        string.IsNullOrWhiteSpace(parsedUri.Host))
                    {
                        return Results.BadRequest(new { error = "Invalid URL: Must be a valid HTTP or HTTPS address with a hostname or IP." });
                    }

                    if (!newUrl.EndsWith("/")) newUrl += "/";

                    // Active network probe unless force=true
                    if (!force)
                    {
                        try
                        {
                            using var probeClient = _httpClientFactory.CreateClient("RemotePulseProbe");
                            probeClient.Timeout = TimeSpan.FromSeconds(3);
                            using var cts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
                            cts.CancelAfter(TimeSpan.FromSeconds(3));
                            var probeResponse = await probeClient.GetAsync(newUrl, cts.Token).ConfigureAwait(false);
                            _logger.LogInformation("Active Hub reachability probe to {Url} returned status {StatusCode}", newUrl, probeResponse.StatusCode);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning("Active Hub reachability probe to {Url} failed: {Error}", newUrl, ex.Message);
                            return Results.BadRequest(new 
                            { 
                                error = $"Could not reach Hub at {parsedUri.Host} ({ex.Message}). Check URL or confirm force apply.",
                                canForce = true
                            });
                        }
                    }

                    _serverUrl = newUrl;
                    await SaveServerUrlToConfigAsync(newUrl);
                    _logger.LogInformation("ServerUrl validated & updated via Local UI to: {Url} (FQDN: {Host})", newUrl, parsedUri.Host);
                    return Results.Ok(new { message = $"Hub address validated and applied ({parsedUri.Host})!", serverUrl = newUrl, fqdn = parsedUri.Host });
                }
            }
            return Results.BadRequest(new { error = "Missing or empty serverUrl parameter." });
        });

        _app.MapPost("/api/unpair", async (HttpContext context) =>
        {
            // CSRF protection: only allow requests originating from our local UI
            if (!IsTrustedLocalOrigin(context))
            {
                var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? context.Request.Headers["Referer"].FirstOrDefault() ?? "unknown";
                _logger.LogWarning("Rejected /api/unpair request from untrusted origin: {Origin}", origin);
                return Results.StatusCode(403);
            }

            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
            string body = await reader.ReadToEndAsync();
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("appId", out var appIdProp) || string.IsNullOrWhiteSpace(appIdProp.GetString()))
            {
                return Results.BadRequest(new { error = "Invalid appId parameter." });
            }

            string appId = appIdProp.GetString()!;
            IReadOnlyList<string> remaining = await _unpairAsync(appId).ConfigureAwait(false);
            _pairedAppIds = remaining;
            _logger.LogInformation("Unpaired App ID {AppId} via Local UI. {Count} pairing(s) remain.", appId, remaining.Count);

            if (remaining.Count == 0)
            {
                // Back to zero pairings - the GET / handler will automatically render the onboarding view.
            }

            return Results.Ok(new { remainingCount = remaining.Count });
        });

        _app.MapPost("/api/pairing/generate", async (HttpContext context) =>
        {
            // CSRF protection: only allow requests originating from our local UI
            if (!IsTrustedLocalOrigin(context))
            {
                var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? context.Request.Headers["Referer"].FirstOrDefault() ?? "unknown";
                _logger.LogWarning("Rejected /api/pairing/generate request from untrusted origin: {Origin}", origin);
                return Results.StatusCode(403);
            }

            if (_pairedAppIds.Count > 0)
            {
                return Results.BadRequest(new { error = "Machine is already paired." });
            }

            var (succeeded, error, pairingUrl, expiresAtUtc) = await GenerateAndPushSecretAsync(context.RequestAborted).ConfigureAwait(false);
            if (succeeded)
            {
                return Results.Ok(new
                {
                    success = true,
                    pairingUrl,
                    expiresAtUtc,
                    validitySeconds = (int)PairingCodeValidity.TotalSeconds
                });
            }

            return Results.Json(new
            {
                success = false,
                error = error ?? "Failed to register pairing code with Hub."
            }, statusCode: 502);
        });

        _app.MapPost("/api/send-log", async (HttpContext context) =>
        {
            // CSRF protection: only allow requests originating from our local UI
            if (!IsTrustedLocalOrigin(context))
            {
                var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? context.Request.Headers["Referer"].FirstOrDefault() ?? "unknown";
                _logger.LogWarning("Rejected /api/send-log request from untrusted origin: {Origin}", origin);
                return Results.StatusCode(403);
            }

            try
            {
                var logTail = GetRecentLogLines(100, filterNoise: true);
                var diagData = new
                {
                    machineId = _machineId,
                    serverUrl = _serverUrl,
                    pairedAppIds = _pairedAppIds,
                    osDescription = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                    osArchitecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
                    processArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
                    frameworkDescription = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                    timestampUtc = DateTime.UtcNow,
                    totalLogLines = logTail.TotalLines,
                    recentLogs = logTail.Lines
                };

                var telemetryEntry = new TelemetryLogEntry
                {
                    Timestamp = DateTime.UtcNow,
                    Source = "Worker",
                    Category = "LocalUiServer",
                    EventName = "ManualWorkerLogUpload",
                    LogLevel = "Information",
                    MachineId = _machineId,
                    Message = $"Manual diagnostic log dump triggered from Local Worker UI for {_machineId}",
                    DataJson = JsonSerializer.Serialize(diagData)
                };

                using var httpClient = _httpClientFactory.CreateClient("RemotePulseHub");
                httpClient.BaseAddress = new Uri(_serverUrl);

                using var hubRequest = new HttpRequestMessage(HttpMethod.Post, "api/telemetry/logs");
                AddSignatureHeaders(hubRequest);
                hubRequest.Content = JsonContent.Create(new[] { telemetryEntry });

                using var response = await httpClient.SendAsync(hubRequest, context.RequestAborted).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("ManualWorkerLogUpload dispatched to Hub successfully from Local UI.");
                    return Results.Ok(new { success = true, message = "Log sent to your Hub." });
                }
                else
                {
                    string errContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    _logger.LogWarning("ManualWorkerLogUpload failed with status {StatusCode}: {Error}", response.StatusCode, errContent);
                    return Results.Json(new { success = false, error = $"Hub returned {response.StatusCode}" }, statusCode: 502);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to dispatch manual log upload from Local UI.");
                return Results.Json(new { success = false, error = ex.Message }, statusCode: 500);
            }
        });

        _app.MapPost("/api/logs/clear", (HttpContext context) =>
        {
            if (!IsTrustedLocalOrigin(context))
            {
                var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? context.Request.Headers["Referer"].FirstOrDefault() ?? "unknown";
                _logger.LogWarning("Rejected /api/logs/clear request from untrusted origin: {Origin}", origin);
                return Results.StatusCode(403);
            }

            try
            {
                FileLoggerProvider.ClearLogFile(AppPaths.GetLogFilePath());
                _logger.LogInformation("Worker log cleared via Local UI.");
                return Results.Ok(new { success = true, clearedAt = DateTime.UtcNow.ToString("HH:mm:ss") + " UTC", message = "Worker log cleared." });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to clear worker log from Local UI.");
                return Results.Json(new { success = false, error = ex.Message }, statusCode: 500);
            }
        });

        _app.MapGet("/api/logs", (HttpContext context) =>
        {
            if (!IsTrustedLocalOrigin(context))
            {
                var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? context.Request.Headers["Referer"].FirstOrDefault() ?? "unknown";
                _logger.LogWarning("Rejected /api/logs request from untrusted origin: {Origin}", origin);
                return Results.StatusCode(403);
            }

            bool filterNoise = !string.Equals(context.Request.Query["filterNoise"].ToString(), "false", StringComparison.OrdinalIgnoreCase);
            var result = GetRecentLogLines(100, filterNoise);
            return Results.Ok(new
            {
                logs = result.Lines,
                totalLines = result.TotalLines,
                suppressedLines = result.SuppressedLines,
                fetchedAt = DateTime.UtcNow.ToString("HH:mm:ss") + " UTC"
            });
        });

        _app.MapGet("/api/status", (HttpContext context) =>
        {
            if (!IsTrustedLocalOrigin(context))
            {
                var origin = context.Request.Headers["Origin"].FirstOrDefault() ?? context.Request.Headers["Referer"].FirstOrDefault() ?? "unknown";
                _logger.LogWarning("Rejected /api/status request from untrusted origin: {Origin}", origin);
                return Results.StatusCode(403);
            }

            string hubFqdn = Uri.TryCreate(_serverUrl, UriKind.Absolute, out Uri? parsedHub) ? parsedHub.Host : _serverUrl;
            string workerVersion = GetWorkerVersion();
            return Results.Ok(new
            {
                version = workerVersion,
                serviceStatus = "Running",
                uptime = GetUptimeString(),
                serverUrl = _serverUrl,
                hubFqdn = hubFqdn,
                pairedCount = _pairedAppIds.Count,
                machineId = _machineId
            });
        });

        // Awaited rather than fire-and-forget: on return the socket is genuinely bound, so
        // callers (and tests) never have to sleep-and-hope the server came up. It also lets an
        // ephemeral port (_port == 0) be read back below.
        await _app.StartAsync().ConfigureAwait(false);

        if (_port == 0)
        {
            var addresses = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
            string? bound = addresses?.Addresses.FirstOrDefault();
            if (bound != null && Uri.TryCreate(bound, UriKind.Absolute, out Uri? boundUri))
            {
                _port = boundUri.Port;
            }
        }

        _logger.LogInformation("Started self-hosted Local Onboarding UI on {BaseUrl}/", BaseUrl);

    }

    /// <summary>
    /// Called when a pairing completes while the onboarding UI is still up. Switches the "/"
    /// handler over to the paired status page and clears active pairing secrets without tearing
    /// down Kestrel itself, so http://localhost:7923/ keeps serving.
    /// </summary>
    public Task TransitionToPairedAsync(IReadOnlyList<string> pairedAppIds, IReadOnlyDictionary<string, string>? pairedAppPublicKeys = null)
    {
        _pairedAppIds = pairedAppIds;
        if (pairedAppPublicKeys != null)
        {
            _pairedAppPublicKeys = pairedAppPublicKeys;
        }
        lock (_secretLock)
        {
            _currentSecret = string.Empty;
            _recentSecrets.Clear();
        }
        _logger.LogInformation("Transitioned Local UI to paired mode ({Count} paired device(s)).", pairedAppIds.Count);
        return Task.CompletedTask;
    }

    public async Task<(bool Succeeded, string? Error, string PairingUrl, DateTimeOffset ExpiresAtUtc)> GenerateAndPushSecretAsync(CancellationToken cancellationToken = default)
    {
        string secret = PairingCrypto.GenerateSecret();
        string pairingId = PairingCrypto.DerivePairingId(secret);
        string workerPublicKey = _keyManager.GetPublicKeyBase64();
        string workerFingerprint = PairingCrypto.ComputePublicKeyFingerprint(workerPublicKey);
        DateTimeOffset generatedAtUtc = DateTimeOffset.UtcNow;
        DateTimeOffset expiresAtUtc = generatedAtUtc.Add(PairingCodeValidity);

        const int maxAttempts = 3;
        bool pushSucceeded = false;
        string? lastError = null;

        for (int attempt = 1; attempt <= maxAttempts && !cancellationToken.IsCancellationRequested; attempt++)
        {
            try
            {
                HttpClient client = _httpClientFactory.CreateClient("RemotePulseHub");
                var submission = new CoPresenceSubmission(
                    PairingId: pairingId,
                    Role: "Client",
                    GeneratedAtUtc: generatedAtUtc,
                    MachineId: _machineId,
                    PublicKey: workerPublicKey
                );
                using var request = new HttpRequestMessage(HttpMethod.Post, "api/pairing/v2")
                {
                    Content = JsonContent.Create(submission)
                };
                request.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);

                // Use an 8-second per-request timeout linked with caller cancellation
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                using HttpResponseMessage response = await client.SendAsync(request, linkedCts.Token).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    pushSucceeded = true;
                    break;
                }

                lastError = $"Hub returned HTTP {response.StatusCode}";
                _logger.LogWarning("Hub rejected co-presence pairing ID push (attempt {Attempt}/{MaxAttempts}): {StatusCode}",
                    attempt, maxAttempts, response.StatusCode);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return (false, "Request canceled.", string.Empty, default);
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                _logger.LogWarning("Failed to push co-presence pairing ID to Hub (attempt {Attempt}/{MaxAttempts}): {Message}",
                    attempt, maxAttempts, ex.Message);
            }

            if (attempt < maxAttempts && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return (false, "Request canceled.", string.Empty, default);
                }
            }
        }

        if (pushSucceeded)
        {
            lock (_secretLock)
            {
                _currentSecret = secret;
                _currentGeneratedAtUtc = generatedAtUtc;
                _recentSecrets.Add((secret, pairingId, expiresAtUtc));
                var now = DateTimeOffset.UtcNow;
                _recentSecrets.RemoveAll(s => s.ExpiresAt < now);
            }
            _logger.LogInformation("Successfully registered on-demand Pairing v2 code with Hub (valid for {Seconds}s).", (int)PairingCodeValidity.TotalSeconds);
            string baseUrl = _serverUrl.TrimEnd('/');
            string fragment = $"k={Uri.EscapeDataString(secret)}&fp={Uri.EscapeDataString(workerFingerprint)}&ts={Uri.EscapeDataString(generatedAtUtc.ToString("o"))}";
            string pairingUrl = $"{baseUrl}/pairing/v2#{fragment}";
            return (true, null, pairingUrl, expiresAtUtc);
        }

        return (false, lastError ?? "Failed to connect to Hub", string.Empty, default);
    }

    /// <summary>
    /// Builds the pairing URL for whatever secret is currently active within its validity window.
    /// </summary>
    public string GetCurrentPairingUrl()
    {
        var (url, _) = GetActivePairingInfo();
        return url;
    }

    private (string PairingUrl, int RemainingSeconds) GetActivePairingInfo()
    {
        string secret;
        DateTimeOffset generatedAtUtc;
        lock (_secretLock)
        {
            secret = _currentSecret;
            generatedAtUtc = _currentGeneratedAtUtc;
        }

        if (string.IsNullOrEmpty(secret))
        {
            return (string.Empty, 0);
        }

        double elapsed = (DateTimeOffset.UtcNow - generatedAtUtc).TotalSeconds;
        int remaining = (int)PairingCodeValidity.TotalSeconds - (int)Math.Floor(elapsed);
        if (remaining <= 0)
        {
            return (string.Empty, 0);
        }

        string baseUrl = _serverUrl.TrimEnd('/');
        string workerFingerprint = PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64());
        string fragment = $"k={Uri.EscapeDataString(secret)}&fp={Uri.EscapeDataString(workerFingerprint)}&ts={Uri.EscapeDataString(generatedAtUtc.ToString("o"))}";
        return ($"{baseUrl}/pairing/v2#{fragment}", remaining);
    }

    private bool IsTrustedLocalOrigin(HttpContext context)
    {
        // 1. Request must originate from loopback IP. A null RemoteIpAddress is untrusted, not
        // exempt - the old `remoteIp != null && !IsLoopback` skipped this check entirely when
        // the connection info was unavailable, silently treating "unknown" as "trusted".
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp is null || !System.Net.IPAddress.IsLoopback(remoteIp))
        {
            return false;
        }

        var origin = context.Request.Headers["Origin"].FirstOrDefault()
                  ?? context.Request.Headers["Referer"].FirstOrDefault();

        // 2. Safe, read-only GET requests from loopback:
        // Browsers omit Origin on same-origin GET. If Origin/Referer is present, verify it;
        // if absent, allow the read from loopback.
        if (HttpMethods.IsGet(context.Request.Method))
        {
            if (string.IsNullOrWhiteSpace(origin))
            {
                return true;
            }

            if (Uri.TryCreate(origin, UriKind.Absolute, out var getUri))
            {
                bool isGetLoopback = string.Equals(getUri.Host, "localhost", StringComparison.OrdinalIgnoreCase) ||
                                     string.Equals(getUri.Host, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                                     string.Equals(getUri.Host, "::1", StringComparison.OrdinalIgnoreCase);
                return isGetLoopback && getUri.Port == _port;
            }

            return false;
        }

        // 3. For state-changing requests (POST/PUT/DELETE):
        // Browsers always attach Origin on POST. Require valid loopback Origin on matching port.
        if (string.IsNullOrWhiteSpace(origin))
        {
            return context.Request.Headers.TryGetValue("Sec-Fetch-Site", out var secFetchSite) &&
                   string.Equals(secFetchSite.FirstOrDefault(), "same-origin", StringComparison.OrdinalIgnoreCase);
        }

        if (Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
        {
            bool isLoopback = string.Equals(originUri.Host, "localhost", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(originUri.Host, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(originUri.Host, "::1", StringComparison.OrdinalIgnoreCase);

            return isLoopback && originUri.Port == _port;
        }

        return false;
    }

    private async Task SaveServerUrlToConfigAsync(string newServerUrl)
    {
        string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");
        try
        {
            // Preserve whatever's already configured for everything except ServerUrl - this used
            // to hardcode AllowUntrustedCertificates=true and PollIntervalSeconds=142
            // unconditionally, silently discarding real settings every time this was used.
            bool allowUntrustedCertificates = false;
            int pollIntervalSeconds = 12;
            int longPollWaitSeconds = 25;
            if (File.Exists(configPath))
            {
                try
                {
                    using var existingDoc = JsonDocument.Parse(await File.ReadAllTextAsync(configPath));
                    if (existingDoc.RootElement.TryGetProperty("RemotePulse", out var existingSection))
                    {
                        if (existingSection.TryGetProperty("AllowUntrustedCertificates", out var propCert)) allowUntrustedCertificates = propCert.GetBoolean();
                        if (existingSection.TryGetProperty("PollIntervalSeconds", out var propInterval)) pollIntervalSeconds = propInterval.GetInt32();
                        if (existingSection.TryGetProperty("LongPollWaitSeconds", out var propWait)) longPollWaitSeconds = propWait.GetInt32();
                    }
                }
                catch
                {
                    // Fall back to the defaults above if the existing file can't be parsed.
                }
            }

            var configData = new
            {
                Logging = new
                {
                    LogLevel = new
                    {
                        Default = "Information",
                        Microsoft_Hosting_Lifetime = "Information"
                    }
                },
                RemotePulse = new
                {
                    ServerUrl = newServerUrl,
                    AllowUntrustedCertificates = allowUntrustedCertificates,
                    MachineId = _machineId,
                    KeyStoragePath = AppPaths.GetKeyStoragePath(),
                    PollIntervalSeconds = pollIntervalSeconds,
                    LongPollWaitSeconds = longPollWaitSeconds
                }
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            string newJson = JsonSerializer.Serialize(configData, options).Replace("Microsoft_Hosting_Lifetime", "Microsoft.Hosting.Lifetime");
            await File.WriteAllTextAsync(configPath, newJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save new ServerUrl to appsettings.json.");
        }
    }

    /// <summary>
    /// Stops the self-hosted Kestrel engine.
    /// </summary>
    public async Task StopAsync()
    {
        if (!_isStarted) return;
        _isStarted = false;

        if (_app != null)
        {
            _logger.LogInformation("Stopping self-hosted Local UI on {BaseUrl}/...", BaseUrl);
            try
            {
                await _app.StopAsync().ConfigureAwait(false);
                await _app.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while disposing Kestrel engine.");
            }
            _app = null;
        }
    }

    /// <summary>
    /// Renders the status page shown at http://localhost:7923/ once this Worker already has at
    /// least one saved pairing - previously nothing listened on this port at all once pairings
    /// existed, which looked identical to the service being broken. Reuses the same visual style
    /// as the onboarding page but swaps the QR/pairing-link section for a paired-clients summary,
    /// and keeps the Hub Server Connection admin panel available for ongoing troubleshooting.
    /// </summary>
    /// <summary>
    /// Log-panel handlers shared by both page templates, so a button rendered on one page can
    /// never point at a function that only the other page defines.
    /// </summary>
    private const string LogPanelScript = """
        var logToastTimer = null;
        function showLogToast(message, isError) {
            var toast = document.getElementById('logToast');
            clearTimeout(logToastTimer);
            toast.style.background = isError ? '#ef4444' : 'var(--input-bg)';
            toast.style.color = isError ? '#ffffff' : 'var(--text-color)';
            toast.style.border = isError ? 'none' : '1px solid var(--input-border)';
            toast.textContent = message;
            toast.style.display = 'block';
            logToastTimer = setTimeout(function () { toast.style.display = 'none'; }, isError ? 6000 : 3000);
        }

        async function sendLog() {
            if (!confirm('Send recent worker log lines to your Hub for troubleshooting?\n\nIncluded: up to 100 recent log lines, this machine\'s ID, paired app IDs, OS and runtime details, and the Hub address.')) return;
            var btn = document.getElementById('sendLogBtn');
            btn.disabled = true;
            btn.textContent = '⏳ Sending...';
            try {
                var res = await fetch('/api/send-log', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
                var data = await res.json();
                if (res.ok && data.success) {
                    showLogToast('✓ ' + (data.message || 'Log sent to your Hub.'), false);
                } else {
                    showLogToast('⚠ ' + (data.error || 'Failed to send log.'), true);
                }
            } catch (err) {
                showLogToast('⚠ Network error: ' + err.message, true);
            } finally {
                btn.disabled = false;
                btn.textContent = '📤 Send Log';
            }
        }

        async function clearLog() {
            if (!confirm('Are you sure you want to clear the local worker log?')) return;
            var btn = document.getElementById('clearLogBtn');
            btn.disabled = true;
            try {
                var res = await fetch('/api/logs/clear', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
                var data = await res.json();
                if (res.ok && data.success) {
                    document.getElementById('logConsole').textContent = '[Logs cleared at ' + data.clearedAt + ']';
                    document.getElementById('logMeta').textContent = '0 log lines recorded';
                    showLogToast('✓ ' + (data.message || 'Worker log cleared.'), false);
                } else {
                    showLogToast('⚠ ' + (data.error || 'Failed to clear log.'), true);
                }
            } catch (err) {
                showLogToast('⚠ Network error: ' + err.message, true);
            } finally {
                btn.disabled = false;
            }
        }

        var FILTER_NOISE_KEY = 'local_filter_noise';
        function initFilterNoise() {
            try {
                var saved = localStorage.getItem(FILTER_NOISE_KEY);
                if (saved !== null) document.getElementById('filterNoise').checked = saved === 'true';
            } catch (e) { }
        }
        function onFilterNoiseChange() {
            try { localStorage.setItem(FILTER_NOISE_KEY, document.getElementById('filterNoise').checked ? 'true' : 'false'); } catch (e) { }
            fetchLogs();
        }

        async function fetchLogs() {
            try {
                var filterBox = document.getElementById('filterNoise');
                var filterNoise = !filterBox || filterBox.checked;
                var res = await fetch('/api/logs?filterNoise=' + (filterNoise ? 'true' : 'false'));
                if (res.ok) {
                    var data = await res.json();
                    var el = document.getElementById('logConsole');
                    var meta = document.getElementById('logMeta');
                    if (el && data.logs) {
                        el.textContent = data.logs.join('\n');
                        el.scrollTop = el.scrollHeight;
                    }
                    if (meta && data.totalLines !== undefined) {
                        var suppressedNote = data.suppressedLines > 0 ? ' (filtered ' + data.suppressedLines + ' polling pings)' : '';
                        meta.textContent = 'Showing latest ' + data.logs.length + ' of ' + data.totalLines + ' lines' + suppressedNote + ' (Updated ' + (data.fetchedAt || '') + ')';
                    }
                }
            } catch (e) { }
        }

        initFilterNoise();
        fetchLogs();
        setInterval(fetchLogs, 5000);
        """;

    private string GetStatusHtml(IReadOnlyList<string> pairedAppIds, string currentServerUrl)
    {
        string hubFqdn = Uri.TryCreate(currentServerUrl, UriKind.Absolute, out Uri? parsedHub) ? parsedHub.Host : currentServerUrl;
        string workerPublicKey = _keyManager.GetPublicKeyBase64();

        string pairedListHtml = string.Join("\n", pairedAppIds.Select(id =>
        {
            string sasHtml = string.Empty;
            if (_pairedAppPublicKeys.TryGetValue(id, out string? appPubKey) && !string.IsNullOrWhiteSpace(appPubKey))
            {
                string sas = PairingCrypto.ComputeSafetyCode(workerPublicKey, appPubKey);
                sasHtml = $"<div style=\"font-size: 12px; color: var(--text-muted); margin-top: 6px;\">Safety Code (SAS): <strong style=\"color: var(--success-color); letter-spacing: 0.08em; font-size: 13px;\">{System.Net.WebUtility.HtmlEncode(sas)}</strong></div>";
            }

            return $"<div class=\"paired-row\"><div class=\"token-box\" style=\"font-family: 'Consolas', monospace;\">" +
                $"<div style=\"font-size: 11px; font-weight: bold; color: var(--accent-color); margin-bottom: 4px;\">📱 Paired Mobile App</div>" +
                $"<div style=\"font-size: 13px; font-weight: bold; word-break: break-all; color: var(--text-color);\">{System.Net.WebUtility.HtmlEncode(id)}</div>" +
                sasHtml +
                $"<div style=\"font-size: 11px; color: var(--text-muted); margin-top: 6px;\">Connected Hub FQDN: <strong style=\"color: var(--accent-color);\">{System.Net.WebUtility.HtmlEncode(hubFqdn)}</strong></div>" +
                $"</div><button type=\"button\" class=\"unpair-btn\" data-appid=\"{System.Net.WebUtility.HtmlEncode(id)}\">Unpair</button></div>";
        }));

        const string template = @"<!DOCTYPE html>
<html lang=""en"">
<head>
    <title>RemotePulse Worker - Paired</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <style>
        :root {
            --bg-color: #0f172a;
            --panel-color: #1e293b;
            --accent-color: #38bdf8;
            --accent-hover: #0284c7;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --input-bg: rgba(15, 23, 42, 0.6);
            --input-border: rgba(255, 255, 255, 0.15);
            --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
            --success-color: #34d399;
        }
        [data-theme=""light""] {
            --bg-color: #f8fafc;
            --panel-color: #ffffff;
            --accent-color: #0284c7;
            --accent-hover: #0369a1;
            --text-color: #0f172a;
            --text-muted: #64748b;
            --input-bg: #ffffff;
            --input-border: #cbd5e1;
            --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.06);
            --success-color: #059669;
        }
        @media (prefers-color-scheme: light) {
            :root:not([data-theme=""dark""]) {
                --bg-color: #f8fafc;
                --panel-color: #ffffff;
                --accent-color: #0284c7;
                --accent-hover: #0369a1;
                --text-color: #0f172a;
                --text-muted: #64748b;
                --input-bg: #ffffff;
                --input-border: #cbd5e1;
                --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.06);
                --success-color: #059669;
            }
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Roboto, -apple-system, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
            transition: background-color 0.25s ease, color 0.25s ease;
        }
        .card {
            background-color: var(--panel-color);
            padding: 30px;
            border-radius: 16px;
            box-shadow: var(--card-shadow);
            text-align: center;
            max-width: 520px;
            width: 100%;
            border: 1px solid rgba(56, 189, 248, 0.2);
            position: relative;
            transition: background-color 0.25s ease, border-color 0.25s ease;
        }
        .theme-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            color: var(--text-color);
            padding: 6px 10px;
            border-radius: 99px;
            cursor: pointer;
            font-size: 13px;
        }
        h1 {
            color: var(--text-color);
            margin-top: 0;
            font-size: 24px;
        }
        h2 {
            color: var(--text-color);
            font-size: 16px;
            margin-top: 24px;
            margin-bottom: 12px;
            text-align: left;
            border-bottom: 1px solid var(--input-border);
            padding-bottom: 6px;
        }
        p {
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-muted);
            margin-bottom: 20px;
        }
        .token-box {
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(56, 189, 248, 0.35);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25), inset 0 1px 2px rgba(255, 255, 255, 0.05);
            padding: 14px 16px;
            border-radius: 10px;
            font-size: 13px;
            word-break: break-all;
            text-align: left;
            color: var(--text-color);
        }
        [data-theme=""light""] .token-box {
            background: #f1f5f9;
            border: 1px solid #cbd5e1;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
            color: #0f172a;
        }
        .paired-row {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 10px;
        }
        .paired-row .token-box {
            flex: 1;
            margin-top: 0;
        }
        .unpair-btn {
            background: transparent;
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.4);
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: bold;
            cursor: pointer;
            white-space: nowrap;
        }
        .unpair-btn:hover {
            background: rgba(239, 68, 68, 0.1);
        }
        .badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            background: var(--success-bg, rgba(52, 211, 153, 0.15));
            color: var(--success-color);
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .admin-panel {
            background: var(--input-bg);
            padding: 18px;
            border-radius: 12px;
            border: 1px solid var(--input-border);
            margin-top: 24px;
            text-align: left;
        }
        label {
            font-size: 12px;
            font-weight: bold;
            color: var(--accent-color);
            display: block;
            margin-bottom: 6px;
        }
        input[type=""text""] {
            width: 100%;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid var(--input-border);
            background: var(--bg-color);
            color: var(--text-color);
            font-size: 14px;
            box-sizing: border-box;
            margin-bottom: 12px;
        }
        .save-btn {
            background-color: var(--accent-color);
            color: #ffffff;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-weight: bold;
            font-size: 13px;
            cursor: pointer;
            width: 100%;
            transition: background 0.2s ease;
        }
        .save-btn:hover {
            background-color: var(--accent-hover);
        }
        #toast {
            display: none;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            margin-top: 10px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class=""card"">
        <button class=""theme-btn"" onclick=""toggleTheme()""><span id=""tIcon"">🌙</span></button>
        
        <div style=""display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 20px; text-align: left;"">
            <div style=""background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 8px; padding: 10px;"">
                <div style=""font-size: 10px; font-weight: bold; text-transform: uppercase; color: var(--text-muted);"">Worker Service</div>
                <div style=""font-size: 13px; font-weight: bold; color: var(--success-color); margin-top: 2px;"">● Running</div>
                <div style=""font-size: 10px; color: var(--text-muted); margin-top: 2px;"">Version: ##WORKER_VERSION##</div>
                <div style=""font-size: 10px; color: var(--text-muted); margin-top: 2px;"">Uptime: ##WORKER_UPTIME##</div>
            </div>
            <div style=""background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 8px; padding: 10px;"">
                <div style=""font-size: 10px; font-weight: bold; text-transform: uppercase; color: var(--text-muted);"">Hub Connection</div>
                <div style=""font-size: 13px; font-weight: bold; color: var(--accent-color); margin-top: 2px;"">● Connected</div>
                <div style=""font-size: 10px; color: var(--text-muted); margin-top: 2px; word-break: break-all;"">FQDN: ##CURRENT_HUB_FQDN##</div>
            </div>
        </div>

        <h1>✓ RemotePulse Worker</h1>
        <div class=""badge"">##PAIRED_COUNT## Client(s) Paired</div>
        <p>This machine is already paired. Unpair a device below if it's no longer needed - this Worker only opens the QR pairing flow again once it has zero saved pairings.</p>

        <div style=""text-align: left;"">
            <label style=""font-size: 11px;"">Paired App ID(s):</label>
            ##PAIRED_LIST##
        </div>

        <div class=""admin-panel"">
            <h2>⚙️ Hub Server Connection</h2>
            <div style=""margin-bottom: 14px; font-size: 13px; padding: 12px 14px; background: rgba(56, 189, 248, 0.08); border-left: 4px solid var(--accent-color); border-radius: 6px;"">
                <div style=""font-size: 11px; font-weight: bold; text-transform: uppercase; color: var(--accent-color); margin-bottom: 2px;"">Connected Hub FQDN</div>
                <div style=""font-size: 15px; font-weight: bold; font-family: 'Consolas', monospace; color: var(--text-color);"">##CURRENT_HUB_FQDN##</div>
                <div style=""font-size: 11px; color: var(--text-muted); margin-top: 4px;"">Full Address: ##CURRENT_SERVER_URL##</div>
            </div>

            <label for=""serverUrlInput"">Configure Custom Hub URL:</label>
            <input type=""text"" id=""serverUrlInput"" value=""##CURRENT_SERVER_URL##"" placeholder=""https://psrun.inspired.codes/"" />

            <button type=""button"" class=""save-btn"" id=""saveConfigBtn"" onclick=""saveConfig()"">Validate & Apply Server Address</button>
            <div id=""toast""></div>
        </div>

        <div class=""admin-panel"" style=""margin-top: 16px;"">
            <div style=""display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;"">
                <h2 style=""margin: 0; border: none; padding: 0;"">🖥️ Worker Console Log Tail</h2>
                <button type=""button"" class=""save-btn"" id=""sendLogBtn"" title=""Send Diagnostic Log to Hub"" style=""width: auto; padding: 4px 10px; font-size: 11px; background: transparent; border: 1px solid var(--accent-color); color: var(--accent-color);"" onclick=""sendLog()"">📤 Send Log</button>
            </div>
            <div style=""display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px; font-size: 11px;"">
                <label style=""color: var(--text-muted); display: inline-flex; align-items: center; gap: 4px;""><input type=""checkbox"" id=""filterNoise"" checked onchange=""onFilterNoiseChange()"" /> Filter polling noise</label>
                <button type=""button"" class=""save-btn"" id=""clearLogBtn"" title=""Clear local worker log"" style=""width: auto; padding: 4px 10px; font-size: 11px; background: transparent; border: 1px solid #ef4444; color: #ef4444;"" onclick=""clearLog()"">🗑️ Clear Log</button>
            </div>
            <div id=""logMeta"" style=""font-size: 10px; color: var(--text-muted); margin-bottom: 6px;"">##LOG_META##</div>
            <pre id=""logConsole"" style=""background: #020617; color: #38bdf8; font-family: 'Consolas', monospace; font-size: 11px; padding: 12px; border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.2); max-height: 220px; overflow-y: auto; text-align: left; white-space: pre-wrap; word-break: break-all; margin: 0;"">##CONSOLE_LOGS##</pre>
            <div id=""logToast"" style=""display: none; padding: 8px; border-radius: 6px; font-size: 11px; margin-top: 8px; text-align: center;""></div>
        </div>
    </div>
    <script>
        function initTheme() {
            var saved = localStorage.getItem('local_theme');
            if (saved === 'light' || saved === 'dark') {
                document.documentElement.setAttribute('data-theme', saved);
                document.getElementById('tIcon').textContent = saved === 'light' ? '☀️' : '🌙';
            } else {
                var prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
                document.getElementById('tIcon').textContent = prefersLight ? '☀️' : '🌙';
            }
        }
        function toggleTheme() {
            var cur = document.documentElement.getAttribute('data-theme');
            var next = cur === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('local_theme', next);
            document.getElementById('tIcon').textContent = next === 'light' ? '☀️' : '🌙';
        }
        initTheme();


        async function saveConfig() {
            var input = document.getElementById('serverUrlInput');
            var btn = document.getElementById('saveConfigBtn');
            var toast = document.getElementById('toast');
            var url = input.value.trim();

            if (!url) {
                toast.style.background = '#ef4444';
                toast.style.color = '#ffffff';
                toast.textContent = '⚠ Please enter a Hub Server address.';
                toast.style.display = 'block';
                return;
            }

            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                toast.style.background = '#ef4444';
                toast.style.color = '#ffffff';
                toast.textContent = '⚠ Invalid format: address must start with http:// or https://';
                toast.style.display = 'block';
                return;
            }

            btn.disabled = true;
            btn.textContent = '⏳ Validating & Applying...';
            toast.style.display = 'none';

            try {
                var response = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ serverUrl: url })
                });
                var data = await response.json();
                if (response.ok) {
                    toast.style.background = 'var(--success-color)';
                    toast.style.color = '#ffffff';
                    toast.textContent = '✓ ' + (data.message || 'Server address validated and applied! Reloading...');
                    toast.style.display = 'block';
                    btn.textContent = '✓ Validated & Applied';
                    setTimeout(function() { window.location.reload(); }, 1200);
                } else {
                    toast.style.background = '#ef4444';
                    toast.style.color = '#ffffff';
                    toast.textContent = '⚠ ' + (data.error || 'Validation failed.');
                    toast.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = 'Validate & Apply Server Address';
                }
            } catch (ex) {
                toast.style.background = '#ef4444';
                toast.style.color = '#ffffff';
                toast.textContent = '⚠ Connection error: ' + ex.message;
                toast.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Validate & Apply Server Address';
            }
        }

        ##LOG_PANEL_SCRIPT##

        async function unpair(appId) {
            if (!confirm('Unpair this device? It will need to scan a new QR code to reconnect.')) return;
            try {
                var response = await fetch('/api/unpair', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ appId: appId })
                });
                if (response.ok) {
                    window.location.reload();
                } else {
                    alert('Error unpairing.');
                }
            } catch (ex) {
                alert('Connection error: ' + ex.message);
            }
        }

        document.querySelectorAll('.unpair-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                unpair(btn.getAttribute('data-appid'));
            });
        });
    </script>
</body>
</html>";

        var logTail = GetRecentLogLines(100, filterNoise: true);
        string initialLogs = System.Net.WebUtility.HtmlEncode(logTail.FormattedTail);
        string logMeta = logTail.TotalLines > 0
            ? $"Showing latest {logTail.Lines.Count} of {logTail.TotalLines} lines" + (logTail.SuppressedLines > 0 ? $" (filtered {logTail.SuppressedLines} polling pings)" : string.Empty)
            : "No logs recorded yet";

        return template
            .Replace("##LOG_PANEL_SCRIPT##", LogPanelScript)
            .Replace("##PAIRED_COUNT##", pairedAppIds.Count.ToString())
            .Replace("##PAIRED_LIST##", pairedListHtml)
            .Replace("##WORKER_UPTIME##", GetUptimeString())
            .Replace("##WORKER_VERSION##", GetWorkerVersion())
            .Replace("##CURRENT_HUB_FQDN##", hubFqdn)
            .Replace("##CURRENT_SERVER_URL##", currentServerUrl)
            .Replace("##CONSOLE_LOGS##", initialLogs)
            .Replace("##LOG_META##", logMeta);
    }

    private string GetOnboardingHtml(string activePairingUrl, int activeRemainingSeconds, string currentServerUrl)
    {
        string hubFqdn = Uri.TryCreate(currentServerUrl, UriKind.Absolute, out Uri? parsedHub) ? parsedHub.Host : currentServerUrl;

        const string template = @"<!DOCTYPE html>
<html lang=""en"">
<head>
    <title>RemotePulse Client Onboarding & Admin Console</title>
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <style>
        :root {
            --bg-color: #0f172a;
            --panel-color: #1e293b;
            --accent-color: #38bdf8;
            --accent-hover: #0284c7;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --input-bg: rgba(15, 23, 42, 0.6);
            --input-border: rgba(255, 255, 255, 0.15);
            --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
            --success-color: #34d399;
        }
        [data-theme=""light""] {
            --bg-color: #f8fafc;
            --panel-color: #ffffff;
            --accent-color: #0284c7;
            --accent-hover: #0369a1;
            --text-color: #0f172a;
            --text-muted: #64748b;
            --input-bg: #ffffff;
            --input-border: #cbd5e1;
            --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.06);
            --success-color: #059669;
        }
        @media (prefers-color-scheme: light) {
            :root:not([data-theme=""dark""]) {
                --bg-color: #f8fafc;
                --panel-color: #ffffff;
                --accent-color: #0284c7;
                --accent-hover: #0369a1;
                --text-color: #0f172a;
                --text-muted: #64748b;
                --input-bg: #ffffff;
                --input-border: #cbd5e1;
                --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.06);
                --success-color: #059669;
            }
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Roboto, -apple-system, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
            transition: background-color 0.25s ease, color 0.25s ease;
        }
        .card {
            background-color: var(--panel-color);
            padding: 30px;
            border-radius: 16px;
            box-shadow: var(--card-shadow);
            text-align: center;
            max-width: 520px;
            width: 100%;
            border: 1px solid rgba(56, 189, 248, 0.2);
            position: relative;
            transition: background-color 0.25s ease, border-color 0.25s ease;
        }
        .theme-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            color: var(--text-color);
            padding: 6px 10px;
            border-radius: 99px;
            cursor: pointer;
            font-size: 13px;
        }
        h1 {
            color: var(--text-color);
            margin-top: 0;
            font-size: 24px;
        }
        h2 {
            color: var(--text-color);
            font-size: 16px;
            margin-top: 24px;
            margin-bottom: 12px;
            text-align: left;
            border-bottom: 1px solid var(--input-border);
            padding-bottom: 6px;
        }
        p {
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-muted);
            margin-bottom: 20px;
        }
        #qrcode {
            background: white;
            padding: 16px;
            border-radius: 12px;
            display: inline-block;
            margin-bottom: 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        #qrcode img {
            display: block;
            margin: 0 auto;
        }
        .token-box {
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(56, 189, 248, 0.35);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25), inset 0 1px 2px rgba(255, 255, 255, 0.05);
            padding: 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
            text-align: left;
            max-height: 90px;
            overflow-y: auto;
            margin-top: 10px;
            color: var(--text-color);
        }
        [data-theme=""light""] .token-box {
            background: #f1f5f9;
            border: 1px solid #cbd5e1;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
            color: #0f172a;
        }
        .badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            background: rgba(56, 189, 248, 0.12);
            color: var(--accent-color);
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .admin-panel {
            background: var(--input-bg);
            padding: 18px;
            border-radius: 12px;
            border: 1px solid var(--input-border);
            margin-top: 24px;
            text-align: left;
        }
        label {
            font-size: 12px;
            font-weight: bold;
            color: var(--accent-color);
            display: block;
            margin-bottom: 6px;
        }
        input[type=""text""] {
            width: 100%;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid var(--input-border);
            background: var(--bg-color);
            color: var(--text-color);
            font-size: 14px;
            box-sizing: border-box;
            margin-bottom: 12px;
        }
        .save-btn {
            background-color: var(--accent-color);
            color: #ffffff;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-weight: bold;
            font-size: 13px;
            cursor: pointer;
            width: 100%;
            transition: background 0.2s ease;
        }
        .save-btn:hover {
            background-color: var(--accent-hover);
        }
        #toast {
            display: none;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            margin-top: 10px;
            text-align: center;
        }
    </style>
    <!-- QR Code Script -->
    <script src=""https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js""></script>
</head>
<body>
    <div class=""card"">
        <button class=""theme-btn"" onclick=""toggleTheme()""><span id=""tIcon"">🌙</span></button>

        <div style=""display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 20px; text-align: left;"">
            <div style=""background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 8px; padding: 10px;"">
                <div style=""font-size: 10px; font-weight: bold; text-transform: uppercase; color: var(--text-muted);"">Worker Service</div>
                <div style=""font-size: 13px; font-weight: bold; color: var(--success-color); margin-top: 2px;"">● Running</div>
                <div style=""font-size: 10px; color: var(--text-muted); margin-top: 2px;"">Version: ##WORKER_VERSION##</div>
                <div style=""font-size: 10px; color: var(--text-muted); margin-top: 2px;"">Uptime: ##WORKER_UPTIME##</div>
            </div>
            <div style=""background: var(--input-bg); border: 1px solid var(--input-border); border-radius: 8px; padding: 10px;"">
                <div style=""font-size: 10px; font-weight: bold; text-transform: uppercase; color: var(--text-muted);"">Hub Connection</div>
                <div style=""font-size: 13px; font-weight: bold; color: var(--accent-color); margin-top: 2px;"">● Connected</div>
                <div style=""font-size: 10px; color: var(--text-muted); margin-top: 2px; word-break: break-all;"">FQDN: ##CURRENT_HUB_FQDN##</div>
            </div>
        </div>

        <h1>RemotePulse Pairing</h1>
        <div class=""badge"">Port 7923 Onboarding & Admin Console</div> 
        <p>Generate a one-time pairing QR code to link this machine with the RemotePulse Mobile App.</p>
        
        <div style=""margin: 15px 0;"">
            <button type=""button"" class=""save-btn"" id=""generateQrBtn"" onclick=""requestPairingCode()"" style=""font-size: 14px; padding: 12px 24px; max-width: 280px; margin: 0 auto; display: block; box-shadow: 0 4px 12px rgba(56, 189, 248, 0.25);"">
                ⚡ Generate Pairing Code
            </button>
            <div id=""qrStatusMsg"" style=""margin-top: 8px; font-size: 12px; color: var(--text-muted); min-height: 18px;""></div>
        </div>

        <div id=""pairingContainer"" style=""display: none; margin-top: 15px;"">
            <div id=""qrcode"" style=""margin: 0 auto 12px auto;""></div>
            
            <div id=""countdownBox"" style=""background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 8px 14px; margin: 0 auto 16px auto; max-width: 320px;"">
                <div style=""display: flex; justify-content: space-between; font-size: 12px; font-weight: bold; margin-bottom: 4px;"">
                    <span style=""color: var(--accent-color);"">⏱️ Code Expiration</span>
                    <span id=""countdownText"" style=""color: var(--text-color);"">90s remaining</span>
                </div>
                <div style=""background: rgba(15, 23, 42, 0.5); border-radius: 4px; height: 6px; overflow: hidden;"">
                    <div id=""countdownBar"" style=""background: var(--accent-color); width: 100%; height: 100%; transition: width 1s linear;""></div>
                </div>
            </div>

            <div style=""text-align: left; position: relative;"">
                <label style=""font-size: 11px;"">Pairing link (valid for 90 seconds):</label>
                <button class=""save-btn"" style=""position: absolute; right: 0; top: -5px; width: auto; padding: 4px 10px; font-size: 11px;"" onclick=""navigator.clipboard.writeText(document.getElementById('tokenText').innerText); this.innerText='Copied!'; setTimeout(()=>this.innerText='Copy Link', 2000);"">Copy Link</button>
                <div id=""tokenText"" class=""token-box"">##PAIRING_URL##</div>
            </div>
        </div>

        <div class=""admin-panel"">
            <h2>⚙️ Hub Server Connection</h2>
            <div style=""margin-bottom: 14px; font-size: 13px; padding: 12px 14px; background: rgba(56, 189, 248, 0.08); border-left: 4px solid var(--accent-color); border-radius: 6px;"">
                <div style=""font-size: 11px; font-weight: bold; text-transform: uppercase; color: var(--accent-color); margin-bottom: 2px;"">Connected Hub FQDN</div>
                <div style=""font-size: 15px; font-weight: bold; font-family: 'Consolas', monospace; color: var(--text-color);"">##CURRENT_HUB_FQDN##</div>
                <div style=""font-size: 11px; color: var(--text-muted); margin-top: 4px;"">Full Address: ##CURRENT_SERVER_URL##</div>
            </div>

            <label for=""serverUrlInput"">Configure Custom Hub URL:</label>
            <input type=""text"" id=""serverUrlInput"" value=""##CURRENT_SERVER_URL##"" placeholder=""https://psrun.inspired.codes/"" />

            <button type=""button"" class=""save-btn"" id=""saveConfigBtn"" onclick=""saveConfig()"">Validate & Apply Server Address</button>
            <div id=""toast""></div>
        </div>

        <div class=""admin-panel"" style=""margin-top: 16px;"">
            <div style=""display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;"">
                <h2 style=""margin: 0; border: none; padding: 0;"">🖥️ Worker Console Log Tail</h2>
                <button type=""button"" class=""save-btn"" id=""sendLogBtn"" title=""Send Diagnostic Log to Hub"" style=""width: auto; padding: 4px 10px; font-size: 11px; background: transparent; border: 1px solid var(--accent-color); color: var(--accent-color);"" onclick=""sendLog()"">📤 Send Log</button>
            </div>
            <div style=""display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px; font-size: 11px;"">
                <label style=""color: var(--text-muted); display: inline-flex; align-items: center; gap: 4px;""><input type=""checkbox"" id=""filterNoise"" checked onchange=""onFilterNoiseChange()"" /> Filter polling noise</label>
                <button type=""button"" class=""save-btn"" id=""clearLogBtn"" title=""Clear local worker log"" style=""width: auto; padding: 4px 10px; font-size: 11px; background: transparent; border: 1px solid #ef4444; color: #ef4444;"" onclick=""clearLog()"">🗑️ Clear Log</button>
            </div>
            <div id=""logMeta"" style=""font-size: 10px; color: var(--text-muted); margin-bottom: 6px;"">##LOG_META##</div>
            <pre id=""logConsole"" style=""background: #020617; color: #38bdf8; font-family: 'Consolas', monospace; font-size: 11px; padding: 12px; border-radius: 8px; border: 1px solid rgba(56, 189, 248, 0.2); max-height: 220px; overflow-y: auto; text-align: left; white-space: pre-wrap; word-break: break-all; margin: 0;"">##CONSOLE_LOGS##</pre>
            <div id=""logToast"" style=""display: none; padding: 8px; border-radius: 6px; font-size: 11px; margin-top: 8px; text-align: center;""></div>
        </div>
    </div>
    <script>
        function initTheme() {
            var saved = localStorage.getItem('local_theme');
            if (saved === 'light' || saved === 'dark') {
                document.documentElement.setAttribute('data-theme', saved);
                document.getElementById('tIcon').textContent = saved === 'light' ? '☀️' : '🌙';
            } else {
                var prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
                document.getElementById('tIcon').textContent = prefersLight ? '☀️' : '🌙';
            }
        }
        function toggleTheme() {
            var cur = document.documentElement.getAttribute('data-theme');
            var next = cur === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('local_theme', next);
            document.getElementById('tIcon').textContent = next === 'light' ? '☀️' : '🌙';
        }
        initTheme();

        var activePairingUrl = '##ACTIVE_PAIRING_URL##';
        var activeRemainingSeconds = parseInt('##ACTIVE_REMAINING_SECONDS##', 10) || 0;
        var countdownTimer = null;
        var qrCodeInstance = null;

        function renderQrCode(url, remainingSeconds) {
            var container = document.getElementById('pairingContainer');
            var qrel = document.getElementById('qrcode');
            var tokenBox = document.getElementById('tokenText');
            var btn = document.getElementById('generateQrBtn');
            var statusMsg = document.getElementById('qrStatusMsg');

            qrel.innerHTML = '';
            qrCodeInstance = new QRCode(qrel, {
                text: url,
                width: 230,
                height: 230,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.L
            });

            tokenBox.innerText = url;
            container.style.display = 'block';
            btn.innerText = '🔄 Regenerate Pairing Code';
            btn.disabled = false;
            statusMsg.innerText = 'Point your RemotePulse Mobile App at the QR code to pair.';
            statusMsg.style.color = 'var(--text-muted)';

            startCountdown(remainingSeconds);
        }

        function startCountdown(seconds) {
            if (countdownTimer) clearInterval(countdownTimer);
            var remaining = seconds;
            var total = 90;

            function updateDisplay() {
                var text = document.getElementById('countdownText');
                var bar = document.getElementById('countdownBar');
                if (text) text.innerText = remaining + 's remaining';
                if (bar) bar.style.width = Math.max(0, (remaining / total) * 100) + '%';
            }
            updateDisplay();

            countdownTimer = setInterval(function() {
                remaining--;
                if (remaining <= 0) {
                    clearInterval(countdownTimer);
                    countdownTimer = null;
                    onPairingExpired();
                } else {
                    updateDisplay();
                }
            }, 1000);
        }

        function onPairingExpired() {
            var container = document.getElementById('pairingContainer');
            var btn = document.getElementById('generateQrBtn');
            var statusMsg = document.getElementById('qrStatusMsg');

            if (container) container.style.display = 'none';
            btn.innerText = '⚡ Generate Pairing Code';
            btn.disabled = false;
            statusMsg.innerText = '⚠️ Previous pairing code expired. Click above to generate a fresh one.';
            statusMsg.style.color = '#f59e0b';
        }

        async function requestPairingCode() {
            var btn = document.getElementById('generateQrBtn');
            var statusMsg = document.getElementById('qrStatusMsg');
            btn.disabled = true;
            btn.innerText = 'Connecting to Hub...';
            statusMsg.innerText = 'Registering secure pairing code with Hub...';
            statusMsg.style.color = 'var(--text-muted)';

            try {
                var res = await fetch('/api/pairing/generate', { method: 'POST' });
                var data = await res.json();
                if (res.ok && data.success && data.pairingUrl) {
                    renderQrCode(data.pairingUrl, data.validitySeconds || 90);
                } else {
                    btn.disabled = false;
                    btn.innerText = '⚡ Generate Pairing Code';
                    statusMsg.innerText = '❌ ' + (data.error || 'Failed to generate code.');
                    statusMsg.style.color = '#ef4444';
                }
            } catch (err) {
                btn.disabled = false;
                btn.innerText = '⚡ Generate Pairing Code';
                statusMsg.innerText = '❌ Network error: ' + err.message;
                statusMsg.style.color = '#ef4444';
            }
        }

        if (activePairingUrl && activeRemainingSeconds > 0) {
            renderQrCode(activePairingUrl, activeRemainingSeconds);
        }

        // Poll for pairing completion far more often than the QR rotates. The Worker's own
        // long-poll to the Hub typically notices a completed scan within a couple of seconds,
        // but this tab had no way to find out until the next scheduled 30s reload - so a scan
        // right after a reload could sit on this page for up to 30s looking like nothing
        // happened. Reloading the moment /api/status reports a pairing swaps this page for the
        // paired status page (see the per-request check in StartAsync) well before that.
        async function checkPairingStatus() {
            try {
                var res = await fetch('/api/status');
                if (res.ok) {
                    var data = await res.json();
                    if (data.pairedCount > 0) {
                        window.location.reload();
                    }
                }
            } catch (e) { }
        }
        setInterval(checkPairingStatus, 2000);


        async function saveConfig() {
            var input = document.getElementById('serverUrlInput');
            var btn = document.getElementById('saveConfigBtn');
            var toast = document.getElementById('toast');
            var url = input.value.trim();

            if (!url) {
                toast.style.background = '#ef4444';
                toast.style.color = '#ffffff';
                toast.textContent = '⚠ Please enter a Hub Server address.';
                toast.style.display = 'block';
                return;
            }

            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                toast.style.background = '#ef4444';
                toast.style.color = '#ffffff';
                toast.textContent = '⚠ Invalid format: address must start with http:// or https://';
                toast.style.display = 'block';
                return;
            }

            btn.disabled = true;
            btn.textContent = '⏳ Validating & Applying...';
            toast.style.display = 'none';

            try {
                var response = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ serverUrl: url })
                });
                var data = await response.json();
                if (response.ok) {
                    toast.style.background = 'var(--success-color)';
                    toast.style.color = '#ffffff';
                    toast.textContent = '✓ ' + (data.message || 'Server address validated and applied! Reloading...');
                    toast.style.display = 'block';
                    btn.textContent = '✓ Validated & Applied';
                    setTimeout(function() { window.location.reload(); }, 1200);
                } else {
                    toast.style.background = '#ef4444';
                    toast.style.color = '#ffffff';
                    toast.textContent = '⚠ ' + (data.error || 'Validation failed.');
                    toast.style.display = 'block';
                    btn.disabled = false;
                    btn.textContent = 'Validate & Apply Server Address';
                }
            } catch (ex) {
                toast.style.background = '#ef4444';
                toast.style.color = '#ffffff';
                toast.textContent = '⚠ Connection error: ' + ex.message;
                toast.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Validate & Apply Server Address';
            }
        }

        ##LOG_PANEL_SCRIPT##
    </script>
</body>
</html>";

        var logTail = GetRecentLogLines(100, filterNoise: true);
        string initialLogs = System.Net.WebUtility.HtmlEncode(logTail.FormattedTail);
        string logMeta = logTail.TotalLines > 0
            ? $"Showing latest {logTail.Lines.Count} of {logTail.TotalLines} lines" + (logTail.SuppressedLines > 0 ? $" (filtered {logTail.SuppressedLines} polling pings)" : string.Empty)
            : "No logs recorded yet";

        string rawPairingUrl = activePairingUrl ?? string.Empty;
        string displayPairingUrl = string.IsNullOrWhiteSpace(rawPairingUrl)
            ? "No active pairing code. Click Generate to create one."
            : rawPairingUrl;

        return template
            .Replace("##LOG_PANEL_SCRIPT##", LogPanelScript)
            .Replace("##PAIRING_URL##", displayPairingUrl)
            .Replace("##ACTIVE_PAIRING_URL##", rawPairingUrl)
            .Replace("##ACTIVE_REMAINING_SECONDS##", activeRemainingSeconds.ToString())
            .Replace("##WORKER_UPTIME##", GetUptimeString())
            .Replace("##WORKER_VERSION##", GetWorkerVersion())
            .Replace("##CURRENT_HUB_FQDN##", hubFqdn)
            .Replace("##CURRENT_SERVER_URL##", currentServerUrl)
            .Replace("##CONSOLE_LOGS##", initialLogs)
            .Replace("##LOG_META##", logMeta);
    }

    private sealed record LogTailResult(IReadOnlyList<string> Lines, int TotalLines, string FormattedTail, int SuppressedLines = 0);

    private static LogTailResult GetRecentLogLines(int maxLines, bool filterNoise)
    {
        try
        {
            string logPath = AppPaths.GetLogFilePath();
            if (!File.Exists(logPath))
            {
                var fallback = new[] { $"[Ready] Log file not found at {logPath} (service may have just started)." };
                return new LogTailResult(fallback, 0, string.Join("\n", fallback));
            }

            using var fileStream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fileStream, Encoding.UTF8);
            var lines = new List<string>();
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                lines.Add(line);
            }

            int total = lines.Count;
            var relevant = filterNoise ? lines.Where(l => !FileLoggerProvider.IsPollingNoise(l)).ToList() : lines;
            int suppressed = total - relevant.Count;
            var tail = relevant.Count > maxLines ? relevant.Skip(relevant.Count - maxLines).ToList() : relevant;
            return new LogTailResult(tail, total, string.Join("\n", tail), suppressed);
        }
        catch (Exception ex)
        {
            var err = new[] { $"Unable to read worker log: {ex.Message}" };
            return new LogTailResult(err, 0, string.Join("\n", err));
        }
    }

    private static string GetWorkerVersion() =>
        System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    private static string GetUptimeString()
    {
        try
        {
            var uptime = DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime();
            return $"{(int)uptime.TotalHours}h {uptime.Minutes}m {uptime.Seconds}s";
        }
        catch
        {
            return "Active";
        }
    }

    private void AddSignatureHeaders(HttpRequestMessage request)
    {
        RequestSigner.AddSignatureHeaders(request, _keyManager, _machineId);
        request.Headers.TryAddWithoutValidation(ProtocolConstants.WorkerVersionHeaderName, PollingWorker.WorkerVersion);
        request.Headers.TryAddWithoutValidation(ProtocolConstants.WorkerCapabilitiesHeaderName, PollingWorker.WorkerCapabilities);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        StopAsync().GetAwaiter().GetResult();
    }
}

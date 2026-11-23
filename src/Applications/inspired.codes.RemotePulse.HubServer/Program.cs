using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using InspiredCodes.RemotePulse.HubServer.Data;
using InspiredCodes.RemotePulse.HubServer.Dashboard;

namespace InspiredCodes.RemotePulse.HubServer;

public class Program
{
    private const int DefaultPollIntervalSeconds = 12;

    /// <summary>
    /// Ceiling on how long a Worker may ask the Hub to hold its poll open. Caps how long a
    /// request occupies a connection, and keeps the window under the idle timeouts that proxies
    /// and load balancers tend to impose on quiet connections.
    /// </summary>
    private const int MaxLongPollWaitSeconds = 90;

    /// <summary>
    /// How often a parked poll re-checks the database even without a signal. This is the safety
    /// net that keeps <see cref="CommandNotifier"/> a latency optimisation rather than a
    /// correctness dependency - a signal lost to a race, or raised on another Hub instance, costs
    /// at most this long instead of the whole wait.
    /// </summary>
    private static readonly TimeSpan LongPollRecheckInterval = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Slack before a check-in counts as missed. Network latency, a busy Worker, and timer drift
    /// all mean a poll due at exactly T arrives a little after it, so without this a healthy
    /// machine would flicker to Degraded on nearly every cycle.
    /// </summary>
    private const int JitterGraceSeconds = 5;

    /// <summary>
    /// Why an authenticated request was rejected - lets <c>AuthFailureResult</c> pick the right
    /// HTTP status code by construction instead of string-matching the error message. The
    /// string-matching version (checking whether the message started with "Unsupported protocol
    /// version") broke silently wherever a caller wrapped the error with its own prefix before
    /// passing it on - see the two SendLogs authentication branches.
    /// </summary>
    private enum AuthFailureReason
    {
        Unauthorized,
        ProtocolVersionMismatch
    }

    /// <summary>
    /// Grades a machine by how many expected check-ins it has missed: none is
    /// <see cref="ClientHealth.Online"/>, one or two is <see cref="ClientHealth.Degraded"/>,
    /// three or more is <see cref="ClientHealth.Offline"/>. Counting in units of the machine's
    /// own reported cadence is what lets a 5s-polling dev box and a slow-polling production one
    /// be judged on the same footing.
    /// </summary>
    private static (ClientHealth Health, int? MissedPolls) EvaluateHealth(DateTime? lastSeenUtc, int? pollIntervalSeconds, DateTime nowUtc)
    {
        if (lastSeenUtc == null)
        {
            return (ClientHealth.Offline, null);
        }

        int interval = Math.Max(1, pollIntervalSeconds ?? DefaultPollIntervalSeconds);
        double grace = Math.Max(JitterGraceSeconds, interval / 2.0);
        double age = (nowUtc - lastSeenUtc.Value).TotalSeconds;

        int missed = (int)Math.Floor(Math.Max(0, age - grace) / interval);

        ClientHealth health = missed switch
        {
            <= 0 => ClientHealth.Online,
            1 or 2 => ClientHealth.Degraded,
            _ => ClientHealth.Offline
        };

        return (health, missed);
    }

    private static string SanitizeTelemetryText(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;

        string sanitized = input;

        // Scrub Windows paths: e.g. C:\Users\... or C:\ProgramData\...
        sanitized = System.Text.RegularExpressions.Regex.Replace(
            sanitized,
            @"[a-zA-Z]:\\[a-zA-Z0-9_\.\-\\]+",
            "[PATH]");

        // Scrub Linux paths: e.g. /home/user/... or /etc/... or /var/...
        sanitized = System.Text.RegularExpressions.Regex.Replace(
            sanitized,
            @"(/(home|root|etc|var|tmp|opt|usr)/[a-zA-Z0-9_\.\-/]+)",
            "[PATH]");

        // Scrub stack trace noise
        int stackIdx = sanitized.IndexOf("   at ", StringComparison.Ordinal);
        if (stackIdx >= 0)
        {
            sanitized = sanitized[..stackIdx].TrimEnd() + " [STACK TRUNCATED]";
        }

        // Scrub secrets / tokens / passwords
        sanitized = System.Text.RegularExpressions.Regex.Replace(
            sanitized,
            @"(?i)(password|secret|token|apikey|key)\s*[:=]\s*['""]?[^'""\s,;]+['""]?",
            "$1=[REDACTED]");

        if (sanitized.Length > 512)
        {
            sanitized = sanitized[..512] + "...";
        }

        return sanitized;
    }

    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        });

        builder.Services.AddDbContext<RemotePulseContext>(options =>
        {
            var connStr = builder.Configuration.GetConnectionString("DefaultConnection");
            if (connStr != null && connStr.StartsWith("InMemory"))
            {
                options.UseInMemoryDatabase(connStr);
            }
            else
            {
                options.UseNpgsql(connStr ?? "Host=localhost;Database=remotepulse;Username=postgres;Password=postgres");
            }
        });

        // Singleton: parked polls and the queue endpoint must meet on the same instance for a
        // signal to reach a waiter.
        builder.Services.AddSingleton<CommandNotifier>();
        builder.Services.AddHostedService<PruneExpiredDataService>();

        // Origins that may call this Hub from a browser (the co-located Blazor App, plus
        // whichever other RemotePulse App instances Peter points at it). Configurable via
        // "AllowedOrigins" (comma-separated) so a new deployment doesn't need a code change.
        // Requests are still signature-authenticated per-call (see VerifyAppRequestAsync /
        // VerifyClientRequestAsync); this narrows who can even reach the API surface from a
        // browser context, it is not the primary auth boundary.
        string[] configuredOrigins = (builder.Configuration["AllowedOrigins"]
                ?? "https://rmpls.inspired.codes,https://psrun.inspired.codes")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowConfiguredOrigins", policy =>
            {
                policy.SetIsOriginAllowed(origin =>
                    {
                        if (configuredOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                        // Local dev convenience: any loopback origin, any scheme/port.
                        if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
                        {
                            return false;
                        }
                        return string.Equals(originUri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                            || (IPAddress.TryParse(originUri.Host, out var originIp) && IPAddress.IsLoopback(originIp));
                    })
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
        });

        builder.Services.AddHsts(options =>
        {
            options.Preload = true;
            options.IncludeSubDomains = true;
            options.MaxAge = TimeSpan.FromDays(365);
        });

        // Rate limits, all per client IP (the real one: UseForwardedHeaders runs before
        // UseRateLimiter). The edge proxy is Caddy on both hosts, and stock Caddy has no rate
        // limiting, so the Hub enforces these itself.
        //
        // A request with no peer address is never limited. Kestrel always sets one, so this only
        // happens in-process (TestServer); without it every test would share a single bucket.
        // The rate-limit tests send X-Forwarded-For to get a real partition.
        //
        // The RateLimiting:* values are read when the options are first resolved, from the built
        // host's IConfiguration, not from builder.Configuration here: WebApplicationFactory's
        // test overrides only reach the built host, so values read here would silently ignore them.
        static int ReadLimit(IConfiguration config, string key, int fallback) =>
            int.TryParse(config[key], out int value) && value > 0 ? value : fallback;

        builder.Services.AddRateLimiter(_ => { });
        builder.Services.AddOptions<Microsoft.AspNetCore.RateLimiting.RateLimiterOptions>().Configure<IConfiguration>((options, config) =>
        {
            int pairingPermitsPerMinute = ReadLimit(config, "RateLimiting:PairingPermitsPerMinute", 10);
            int apiPermitsPerSecond = ReadLimit(config, "RateLimiting:ApiPermitsPerSecond", 10);
            int apiBurst = ReadLimit(config, "RateLimiting:ApiBurst", 20);
            int supportReportsPerMinute = ReadLimit(config, "RateLimiting:SupportReportsPerMinute", 2);
            int supportReportBurst = ReadLimit(config, "RateLimiting:SupportReportBurst", 3);

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = (context, _) =>
            {
                if (context.Lease.TryGetMetadata(System.Threading.RateLimiting.MetadataName.RetryAfter, out TimeSpan retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter =
                        ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
                }
                return ValueTask.CompletedTask;
            };

            // Every /api/* request: 10 r/s sustained with a burst of 20 (defaults). /ops and /
            // are not covered: /ops is only reachable through the SSH tunnel and is token-gated.
            options.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(context =>
            {
                string? remoteIp = context.Connection.RemoteIpAddress?.ToString();
                if (remoteIp is null || !context.Request.Path.StartsWithSegments("/api"))
                {
                    return System.Threading.RateLimiting.RateLimitPartition.GetNoLimiter(string.Empty);
                }
                return System.Threading.RateLimiting.RateLimitPartition.GetTokenBucketLimiter(remoteIp, _ => new System.Threading.RateLimiting.TokenBucketRateLimiterOptions
                {
                    TokenLimit = apiBurst,
                    TokensPerPeriod = apiPermitsPerSecond,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
            });

            // SEC-5: pairing requests, 10/min (default).
            options.AddPolicy("PairingRateLimit", context =>
            {
                string? remoteIp = context.Connection.RemoteIpAddress?.ToString();
                if (remoteIp is null)
                {
                    return System.Threading.RateLimiting.RateLimitPartition.GetNoLimiter(string.Empty);
                }
                return System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(remoteIp, _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                {
                    PermitLimit = pairingPermitsPerMinute,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                });
            });

            // The unauthenticated support report: 2/min sustained with a burst of 3 (defaults).
            // On top of the global /api/* limit, which it is also subject to.
            options.AddPolicy("SupportReportRateLimit", context =>
            {
                string? remoteIp = context.Connection.RemoteIpAddress?.ToString();
                if (remoteIp is null)
                {
                    return System.Threading.RateLimiting.RateLimitPartition.GetNoLimiter(string.Empty);
                }
                return System.Threading.RateLimiting.RateLimitPartition.GetTokenBucketLimiter(remoteIp, _ => new System.Threading.RateLimiting.TokenBucketRateLimiterOptions
                {
                    TokenLimit = supportReportBurst,
                    TokensPerPeriod = 1,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(60.0 / supportReportsPerMinute),
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
            });
        });

        var app = builder.Build();

        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            if (db.Database.IsRelational())
            {
                await db.Database.MigrateAsync();
            }
            else
            {
                await db.Database.EnsureCreatedAsync();
            }
        }

        // SEC-5 follow-up: the rate limiter below keys on Connection.RemoteIpAddress, which is
        // the reverse proxy's address (Caddy), not the real caller's, unless this middleware
        // rewrites it from X-Forwarded-For first. Trusting the immediate peer unconditionally
        // (KnownNetworks/KnownProxies cleared, rather than listing specific proxy IPs) is safe
        // ONLY because the Hub container publishes no public port: our deployments publish
        // none, or just a loopback port for the /ops SSH tunnel. Anyone self-hosting the Hub
        // must keep it that way. Besides the reverse proxy, only someone
        // already logged into the host can connect to it directly, so there is no untrusted party
        // in a position to forge this header. Must run before UseRateLimiter() so the rewritten
        // address is what it partitions
        // on.
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
                | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto
        };
        forwardedHeadersOptions.KnownNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();
        app.UseForwardedHeaders(forwardedHeadersOptions);

        app.UseCors("AllowConfiguredOrigins");
        app.UseRateLimiter();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        static (bool IsSupported, string? Error) CheckProtocolVersion(HttpRequest request)
        {
            if (request.Headers.TryGetValue(ProtocolConstants.VersionHeaderName, out var versionValues))
            {
                string versionStr = versionValues.First() ?? string.Empty;
                if (int.TryParse(versionStr, out int clientVersion) && clientVersion > ProtocolConstants.CurrentVersionNumber)
                {
                    return (false, $"Unsupported protocol version {versionStr}. Hub supports up to {ProtocolConstants.CurrentVersionNumber}.");
                }
            }
            return (true, null);
        }

        static IResult AuthFailureResult(AuthFailureReason reason, string error)
        {
            int statusCode = reason == AuthFailureReason.ProtocolVersionMismatch
                ? StatusCodes.Status426UpgradeRequired
                : StatusCodes.Status401Unauthorized;
            return Results.Json(new { error }, statusCode: statusCode);
        }

        async Task<(bool IsValid, AuthFailureReason Reason, string Error)> VerifyClientRequestAsync(HttpRequest request, string machineId, RemotePulseContext db)
        {
            var (isVersionSupported, versionError) = CheckProtocolVersion(request);
            if (!isVersionSupported)
            {
                return (false, AuthFailureReason.ProtocolVersionMismatch, versionError!);
            }

            var client = await db.Clients.FirstOrDefaultAsync(c => c.MachineId == machineId);
            if (client == null)
            {
                return (false, AuthFailureReason.Unauthorized, "Client not registered.");
            }

            if (!request.Headers.TryGetValue("X-Timestamp", out var timestampValues) ||
                !request.Headers.TryGetValue("X-Nonce", out var nonceValues) ||
                !request.Headers.TryGetValue("X-Signature", out var signatureValues))
            {
                return (false, AuthFailureReason.Unauthorized, "Missing signature headers.");
            }

            string timestamp = timestampValues.First() ?? string.Empty;
            string nonce = nonceValues.First() ?? string.Empty;
            string signatureBase64 = signatureValues.First() ?? string.Empty;

            if (DateTimeOffset.TryParse(timestamp, out var parsedTime))
            {
                var diff = DateTimeOffset.UtcNow - parsedTime;
                if (Math.Abs(diff.TotalMinutes) > 5.0)
                {
                    return (false, AuthFailureReason.Unauthorized, "Request expired or clock skew too high.");
                }
            }
            else
            {
                return (false, AuthFailureReason.Unauthorized, "Invalid timestamp format.");
            }

            string nonceKey = $"client:{machineId}:{nonce}";
            if (await db.SeenNonces.AnyAsync(n => n.NonceKey == nonceKey && n.Expiry > DateTime.UtcNow))
            {
                return (false, AuthFailureReason.Unauthorized, "Replayed request detected (duplicate nonce).");
            }

            try
            {
                string message = RequestSigner.CreateSignatureMessage(request.Method, request.Path.Value ?? "/", machineId, timestamp, nonce);
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] signatureBytes = Convert.FromBase64String(signatureBase64);

                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(client.PublicKey), out _);

                bool isValid = ecdsa.VerifyData(messageBytes, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                if (!isValid)
                {
                    return (false, AuthFailureReason.Unauthorized, "Invalid cryptographic signature.");
                }

                // Only record nonce after signature is confirmed valid
                db.SeenNonces.Add(new SeenNonce { NonceKey = nonceKey, Expiry = DateTime.UtcNow.AddMinutes(10) });

                // Liveness heartbeat for the App's watchdog. Every authenticated Worker request
                // funnels through here (poll, result post, pairing confirm), the Client row is
                // already loaded, and we're already saving - so this costs no extra round trip.
                // Stamping it only on the verified path is what keeps it trustworthy: an
                // unauthenticated caller can't make a dead machine look alive.
                client.LastSeenUtc = DateTime.UtcNow;
                if (request.Headers.TryGetValue("X-Poll-Interval", out var pollIntervalValues) &&
                    int.TryParse(pollIntervalValues.First(), out int reportedInterval) &&
                    reportedInterval > 0)
                {
                    client.PollIntervalSeconds = reportedInterval;
                }

                // Worker 1.2.0+ self-reports its version and feature tokens on every signed request.
                // A *poll* without them can only come from an older Worker, so it clears what was
                // stored - otherwise a Worker downgraded from 1.2 would keep advertising features it
                // no longer has. Other requests without the header leave the values alone.
                if (request.Headers.TryGetValue(ProtocolConstants.WorkerVersionHeaderName, out var workerVersionValues))
                {
                    client.WorkerVersion = WorkerReportedInfo.NormalizeVersion(workerVersionValues.First());
                    client.WorkerCapabilities = WorkerReportedInfo.NormalizeCapabilities(
                        request.Headers.TryGetValue(ProtocolConstants.WorkerCapabilitiesHeaderName, out var capabilityValues)
                            ? capabilityValues.ToString()
                            : null);
                }
                else if (HttpMethods.IsGet(request.Method) &&
                         string.Equals(request.Path.Value, "/api/commands/poll", StringComparison.OrdinalIgnoreCase))
                {
                    client.WorkerVersion = null;
                    client.WorkerCapabilities = null;
                }

                await db.SaveChangesAsync();
                return (true, AuthFailureReason.Unauthorized, string.Empty);
            }
            catch (Exception ex)
            {
                // Don't leak exception details (crypto internals, malformed-input specifics) to
                // the caller - log server-side, return a generic failure like every other branch.
                app.Logger.LogWarning(ex, "Client signature verification threw for {MachineId}.", machineId);
                return (false, AuthFailureReason.Unauthorized, "Signature verification failed.");
            }
        }

        async Task<(bool IsValid, AuthFailureReason Reason, string Error)> VerifyAppRequestAsync(HttpRequest request, string appId, RemotePulseContext db)
        {
            var (isVersionSupported, versionError) = CheckProtocolVersion(request);
            if (!isVersionSupported)
            {
                return (false, AuthFailureReason.ProtocolVersionMismatch, versionError!);
            }

            var pairing = await db.Pairings.FirstOrDefaultAsync(p => p.AppId == appId && p.IsLocked);
            if (pairing == null)
            {
                return (false, AuthFailureReason.Unauthorized, "App is not paired or pairing not locked.");
            }

            if (!request.Headers.TryGetValue("X-Timestamp", out var timestampValues) ||
                !request.Headers.TryGetValue("X-Nonce", out var nonceValues) ||
                !request.Headers.TryGetValue("X-Signature", out var signatureValues))
            {
                return (false, AuthFailureReason.Unauthorized, "Missing signature headers.");
            }

            string timestamp = timestampValues.First() ?? string.Empty;
            string nonce = nonceValues.First() ?? string.Empty;
            string signatureBase64 = signatureValues.First() ?? string.Empty;

            if (DateTimeOffset.TryParse(timestamp, out var parsedTime))
            {
                var diff = DateTimeOffset.UtcNow - parsedTime;
                if (Math.Abs(diff.TotalMinutes) > 5.0)
                {
                    return (false, AuthFailureReason.Unauthorized, "Request expired or clock skew too high.");
                }
            }
            else
            {
                return (false, AuthFailureReason.Unauthorized, "Invalid timestamp format.");
            }

            string nonceKey = $"app:{appId}:{nonce}";
            if (await db.SeenNonces.AnyAsync(n => n.NonceKey == nonceKey && n.Expiry > DateTime.UtcNow))
            {
                return (false, AuthFailureReason.Unauthorized, "Replayed request detected (duplicate nonce).");
            }

            try
            {
                string method = request.Method.ToUpperInvariant();
                string path = request.Path.Value ?? "/";
                string message = $"{method}:{path}:{appId}:{timestamp}:{nonce}";
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] signatureBytes = Convert.FromBase64String(signatureBase64);

                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pairing.AppPublicKey), out _);

                bool isValid = ecdsa.VerifyData(messageBytes, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                if (!isValid)
                {
                    return (false, AuthFailureReason.Unauthorized, "Invalid App signature.");
                }

                // Only record nonce after signature is confirmed valid
                db.SeenNonces.Add(new SeenNonce { NonceKey = nonceKey, Expiry = DateTime.UtcNow.AddMinutes(10) });
                await db.SaveChangesAsync();
                return (true, AuthFailureReason.Unauthorized, string.Empty);
            }
            catch (Exception ex)
            {
                app.Logger.LogWarning(ex, "App signature verification threw for {AppId}.", appId);
                return (false, AuthFailureReason.Unauthorized, "Signature verification failed.");
            }
        }

        // Co-presence pairing ticket lifetime: on-demand pairing code is valid for 90 seconds.
        const int CoPresenceValiditySeconds = 90;

        async Task<IResult> FinalizeCoPresenceAsync(PendingCoPresence row, RemotePulseContext db)
        {
            // Identity-hijack guard (trust-on-first-use, immutable after): a MachineId that
            // already belongs to a different registered key can't be silently re-claimed just
            // because someone produced a matching co-presence secret.
            var existingClient = await db.Clients.FirstOrDefaultAsync(c => c.MachineId == row.ClientMachineId);
            if (existingClient != null && existingClient.PublicKey != row.ClientPublicKey)
            {
                db.PendingCoPresences.Remove(row);
                await db.SaveChangesAsync();
                return Results.Json(new { error = "MachineId already registered with a different key." }, statusCode: StatusCodes.Status409Conflict);
            }

            if (existingClient == null)
            {
                db.Clients.Add(new Client { MachineId = row.ClientMachineId!, PublicKey = row.ClientPublicKey! });
            }

            // SEC-2: In this tier, each Worker is strictly 1:1 with Mobile.
            // If this Worker is already paired with a different Mobile device (IsLocked = true),
            // reject the pairing with 409 Conflict.
            var conflictingPairing = await db.Pairings.FirstOrDefaultAsync(p => p.MachineId == row.ClientMachineId && p.AppId != row.AppId && p.IsLocked);
            if (conflictingPairing != null)
            {
                db.PendingCoPresences.Remove(row);
                await db.SaveChangesAsync();
                return Results.Json(new { error = "This Worker is already paired with a different Mobile device. Unpair it from the Worker's local onboarding page first." }, statusCode: StatusCodes.Status409Conflict);
            }

            var existingPairing = await db.Pairings.FirstOrDefaultAsync(p => p.MachineId == row.ClientMachineId && p.AppId == row.AppId);
            if (existingPairing != null)
            {
                existingPairing.AppPublicKey = row.AppPublicKey!;
                existingPairing.IsLocked = true;
                existingPairing.PairingId = row.PairingId;
                existingPairing.AppBindTag = row.AppBindTag;
                // Re-announce on every (re-)match, in case the App's key changed since the Client last learned it.
                existingPairing.AnnouncedToClientAtUtc = null;
            }
            else
            {
                db.Pairings.Add(new Pairing
                {
                    MachineId = row.ClientMachineId!,
                    AppId = row.AppId!,
                    AppPublicKey = row.AppPublicKey!,
                    IsLocked = true,
                    PairingId = row.PairingId,
                    AppBindTag = row.AppBindTag
                });
            }

            db.PendingCoPresences.Remove(row);
            await db.SaveChangesAsync();

            // The App learns the Client's public key here and verifies it against the SHA-256
            // fingerprint (fp) from the QR fragment before saving. The Client learns the App's
            // public key separately via GET /api/commands/poll alongside pid and AppBindTag.
            return Results.Ok(new { status = "matched", machineId = row.ClientMachineId, clientPublicKey = row.ClientPublicKey, appId = row.AppId });
        }

        app.MapPost("/api/pairing/v2", async (HttpRequest request, CoPresenceSubmission submission, RemotePulseContext db) =>
        {
            var (isVersionSupported, versionError) = CheckProtocolVersion(request);
            if (!isVersionSupported)
            {
                return AuthFailureResult(AuthFailureReason.ProtocolVersionMismatch, versionError!);
            }

            if (!PairingCrypto.IsValidBase64Url256(submission.PairingId))
            {
                return Results.BadRequest("PairingId is required and must be 43 base64url characters.");
            }

            DateTime now = DateTime.UtcNow;

            if (submission.Role == "Client")
            {
                if (string.IsNullOrWhiteSpace(submission.MachineId) || string.IsNullOrWhiteSpace(submission.PublicKey))
                {
                    return Results.BadRequest("MachineId and PublicKey are required for Role=Client.");
                }

                PendingCoPresence? row = await db.PendingCoPresences.FindAsync(submission.PairingId);
                if (row == null)
                {
                    row = new PendingCoPresence { PairingId = submission.PairingId };
                    db.PendingCoPresences.Add(row);
                }

                row.ClientMachineId = submission.MachineId;
                row.ClientPublicKey = submission.PublicKey;
                row.ExpiresAtUtc = now.AddSeconds(CoPresenceValiditySeconds);
                await db.SaveChangesAsync();

                if (row.AppId != null)
                {
                    return await FinalizeCoPresenceAsync(row, db);
                }
                return Results.Ok(new { status = "waiting-for-app" });
            }

            if (submission.Role == "App")
            {
                if (string.IsNullOrWhiteSpace(submission.AppId) || string.IsNullOrWhiteSpace(submission.AppPublicKey))
                {
                    return Results.BadRequest("AppId and AppPublicKey are required for Role=App.");
                }

                if (!PairingCrypto.IsValidBase64Url256(submission.AppBindTag))
                {
                    return Results.BadRequest("AppBindTag is required and must be 43 base64url characters for Role=App.");
                }

                PendingCoPresence? row = await db.PendingCoPresences.FindAsync(submission.PairingId);
                if (row == null || row.ClientMachineId == null)
                {
                    return Results.Json(new { error = "Unknown or not-yet-issued pairing ID." }, statusCode: StatusCodes.Status404NotFound);
                }

                if (row.ExpiresAtUtc <= now)
                {
                    db.PendingCoPresences.Remove(row);
                    await db.SaveChangesAsync();
                    return Results.Json(new { error = "Pairing code expired. Rescan the QR code." }, statusCode: StatusCodes.Status410Gone);
                }

                // SEC-6: Proof-of-Possession signature is mandatory, not just verified-if-present.
                // Without it, a caller who learns PairingId could register an arbitrary AppPublicKey
                // they do not hold the private key for. Verified over UTF8(PairingId).
                if (string.IsNullOrEmpty(submission.SecretSignature))
                {
                    return Results.BadRequest("SecretSignature is required for Role=App.");
                }
                try
                {
                    using var appEcdsa = ECDsa.Create();
                    appEcdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(submission.AppPublicKey), out _);
                    byte[] pairingIdBytes = Encoding.UTF8.GetBytes(submission.PairingId);
                    byte[] signatureBytes = Convert.FromBase64String(submission.SecretSignature);
                    bool isPoPValid = appEcdsa.VerifyData(
                        pairingIdBytes,
                        signatureBytes,
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

                    if (!isPoPValid)
                    {
                        return Results.BadRequest("Invalid secret signature.");
                    }
                }
                catch
                {
                    return Results.BadRequest("Invalid secret signature format.");
                }

                row.AppId = submission.AppId;
                row.AppPublicKey = submission.AppPublicKey;
                row.AppBindTag = submission.AppBindTag;
                await db.SaveChangesAsync();

                return await FinalizeCoPresenceAsync(row, db);
            }

            return Results.BadRequest("Role must be 'Client' or 'App'.");
        }).RequireRateLimiting("PairingRateLimit");

        app.MapPost("/api/pairing/release", async (HttpRequest request, ReleasePairingRequest body, RemotePulseContext db) =>
        {
            if (!request.Headers.TryGetValue("X-Client-Id", out var clientIdValues))
            {
                return Results.BadRequest("Missing X-Client-Id header.");
            }
            string machineId = clientIdValues.First() ?? string.Empty;

            var (isValid, reason, error) = await VerifyClientRequestAsync(request, machineId, db);
            if (!isValid)
            {
                return AuthFailureResult(reason, error);
            }

            if (!string.IsNullOrWhiteSpace(body?.AppId))
            {
                var pairing = await db.Pairings.FirstOrDefaultAsync(p => p.MachineId == machineId && p.AppId == body.AppId);
                if (pairing != null)
                {
                    db.Pairings.Remove(pairing);
                    await db.SaveChangesAsync();
                }
            }

            return Results.Ok(new { status = "released" });
        });

        app.MapGet("/api/commands/poll", async (HttpRequest request, RemotePulseContext db, CommandNotifier notifier, CancellationToken cancellationToken) =>
        {
            if (!request.Headers.TryGetValue("X-Client-Id", out var clientIdValues))
            {
                return Results.BadRequest("Missing X-Client-Id header.");
            }
            string machineId = clientIdValues.First() ?? string.Empty;

            var (isValid, reason, error) = await VerifyClientRequestAsync(request, machineId, db);
            if (!isValid)
            {
                return AuthFailureResult(reason, error);
            }

            // Long-poll window. Absent or 0 keeps the original fire-and-return behaviour, so a
            // Worker from before this feature carries on working unchanged.
            int waitSeconds = 0;
            if (request.Query.TryGetValue("wait", out var waitValues) &&
                int.TryParse(waitValues.FirstOrDefault(), out int requestedWait))
            {
                waitSeconds = Math.Clamp(requestedWait, 0, MaxLongPollWaitSeconds);
            }

            // Subscribe before the first look at the queue: a command arriving between the check
            // and the wait would otherwise signal nobody and park anyway (lost wakeup).
            using CommandNotifier.Subscription subscription = notifier.Subscribe(machineId);

            DateTime deadline = DateTime.UtcNow.AddSeconds(waitSeconds);

            while (true)
            {
                IResult? work = await TryTakeWorkAsync(machineId, db);
                if (work != null)
                {
                    return work;
                }

                TimeSpan remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero || cancellationToken.IsCancellationRequested)
                {
                    return Results.NoContent();
                }

                // Wake on the signal, but never sleep longer than the re-check interval: that
                // bounds how long a missed signal (or one raised on another Hub instance) can
                // delay delivery to a few seconds rather than the whole window.
                TimeSpan sleep = remaining < LongPollRecheckInterval ? remaining : LongPollRecheckInterval;
                await subscription.WaitAsync(sleep, cancellationToken);
            }
        });

        // Returns the next thing this machine should act on, or null when its queue is empty.
        async Task<IResult?> TryTakeWorkAsync(string machineId, RemotePulseContext db)
        {
            // Worker liveness timestamp update is handled once per verified request inside
            // VerifyClientRequestAsync. Do not add a redundant db.SaveChangesAsync() call here.

            // SEC-2 co-presence: if this Worker has an unannounced v2 pairing, deliver the announcement
            // before any pending commands. The Worker needs the App's public key (to verify signed
            // scripts) before it can run commands from that App. Pre-v2 rows with a null PairingId
            // or AppBindTag are skipped so the Hub never emits a malformed 'PAIRING:a:b::'.
            var unannouncedPairing = await db.Pairings
                .FirstOrDefaultAsync(p => p.MachineId == machineId
                    && p.AnnouncedToClientAtUtc == null
                    && p.IsLocked
                    && !string.IsNullOrEmpty(p.PairingId)
                    && !string.IsNullOrEmpty(p.AppBindTag));

            if (unannouncedPairing != null)
            {
                try
                {
                    unannouncedPairing.AnnouncedToClientAtUtc = DateTime.UtcNow;
                    await db.SaveChangesAsync();

                    string pairingAnnouncement = $"PAIRING:{unannouncedPairing.AppId}:{unannouncedPairing.AppPublicKey}:{unannouncedPairing.PairingId}:{unannouncedPairing.AppBindTag}";
                    return Results.Ok(new ServerCommand(
                        CommandId: "PAIRING-ANNOUNCE",
                        Script: pairingAnnouncement,
                        ExecutionMode: ExecutionMode.RunAsCurrentUser,
                        IsHandshake: true,
                        TimeoutSeconds: 30));
                }
                catch (DbUpdateConcurrencyException)
                {
                    return null;
                }
            }

            var nextCommand = await db.CommandQueue.OrderBy(c => c.DateCreated).FirstOrDefaultAsync(c => c.MachineId == machineId);
            if (nextCommand != null)
            {
                // Removing the command is the only trace a pickup otherwise leaves, so record it: if the
                // Worker then hangs or dies, this is how the Hub can tell "never picked up" from "picked up, no result".
                DateTime pickedUpAtUtc = DateTime.UtcNow;
                string timeoutText = nextCommand.TimeoutSeconds is int t ? $"{t}s timeout" : "no timeout";
                var breadcrumb = new SystemLogEntity
                {
                    Timestamp = pickedUpAtUtc,
                    Source = "Hub",
                    MachineId = machineId,
                    LogLevel = "Information",
                    Category = "Commands",
                    EventName = "CommandPickedUp",
                    Message = $"Command [{nextCommand.CommandId}] picked up by Worker {machineId} ({nextCommand.ExecutionMode}, {timeoutText}).",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        commandId = nextCommand.CommandId,
                        executionMode = nextCommand.ExecutionMode.ToString(),
                        timeoutSeconds = nextCommand.TimeoutSeconds,
                        queuedAtUtc = nextCommand.DateCreated,
                        waitedInQueueMs = Math.Round((pickedUpAtUtc - nextCommand.DateCreated).TotalMilliseconds)
                    })
                };

                try
                {
                    db.CommandQueue.Remove(nextCommand);
                    db.SystemLogs.Add(breadcrumb);
                    await db.SaveChangesAsync();
                    return Results.Ok(new ServerCommand(nextCommand.CommandId, nextCommand.Script, nextCommand.ExecutionMode, nextCommand.IsHandshake, nextCommand.TimeoutSeconds));
                }
                catch (DbUpdateConcurrencyException)
                {
                    // Another poll took this command. The context is reused by the long-poll loop, so drop the
                    // unsaved breadcrumb or a later SaveChanges would record a pickup that never happened.
                    db.Entry(breadcrumb).State = EntityState.Detached;
                    return null;
                }
            }

            return null;
        }

        app.MapPost("/api/commands/results", async (HttpRequest request, CommandResult resultPayload, RemotePulseContext db) =>
        {
            if (!request.Headers.TryGetValue("X-Client-Id", out var clientIdValues))
            {
                return Results.BadRequest("Missing X-Client-Id header.");
            }
            string machineId = clientIdValues.First() ?? string.Empty;

            var (isValid, reason, error) = await VerifyClientRequestAsync(request, machineId, db);
            if (!isValid)
            {
                return AuthFailureResult(reason, error);
            }

            if (resultPayload.EncryptedPayload != null && resultPayload.EncryptedPayload.Length > 10 * 1024 * 1024)
            {
                return Results.BadRequest("EncryptedPayload exceeds 10MB limit.");
            }

            var entity = new CommandResultEntity
            {
                CommandId = resultPayload.CommandId,
                MachineId = machineId,
                Success = resultPayload.Success,
                DurationMs = resultPayload.DurationMs,
                IsEncrypted = resultPayload.IsEncrypted,
                EncryptedPayload = resultPayload.EncryptedPayload,
                RejectionReason = resultPayload.RejectionReason
            };
            db.CommandResults.Add(entity);
            await db.SaveChangesAsync();

            return Results.Ok();
        });

        app.MapPost("/api/commands/queue", async (HttpRequest request, QueueCommandRequest cmdReq, RemotePulseContext db, CommandNotifier notifier) =>
        {
            if (!request.Headers.TryGetValue("X-App-Id", out var appIdValues))
            {
                return Results.BadRequest("Missing X-App-Id header.");
            }
            string appId = appIdValues.First() ?? string.Empty;

            (bool isValid, AuthFailureReason reason, string? error) = await VerifyAppRequestAsync(request, appId, db);
            if (!isValid)
            {
                return AuthFailureResult(reason, error);
            }

            bool isPaired = await db.Pairings.AnyAsync(p => p.MachineId == cmdReq.MachineId && p.AppId == appId && p.IsLocked);
            if (!isPaired)
            {
                return Results.Json(new { error = "App is not paired with this machine." }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(cmdReq.CommandId) || cmdReq.CommandId.Length > 128)
            {
                return Results.BadRequest("CommandId must be between 1 and 128 characters.");
            }

            if (string.IsNullOrWhiteSpace(cmdReq.EncryptedScript) || cmdReq.EncryptedScript.Length > 1048576)
            {
                return Results.BadRequest("EncryptedScript is required and must not exceed 1MB.");
            }

            if (cmdReq.TimeoutSeconds.HasValue && cmdReq.TimeoutSeconds.Value is < 1 or > 3600)
            {
                return Results.BadRequest("TimeoutSeconds must be between 1 and 3600.");
            }

            // VAL-2: reject duplicate CommandId across queue and historical results
            if (await db.CommandQueue.AnyAsync(c => c.CommandId == cmdReq.CommandId) ||
                await db.CommandResults.AnyAsync(r => r.CommandId == cmdReq.CommandId))
            {
                return Results.Conflict("CommandId already exists.");
            }

            db.CommandQueue.Add(new ServerCommandEntity
            {
                CommandId = cmdReq.CommandId,
                MachineId = cmdReq.MachineId,
                Script = cmdReq.EncryptedScript,
                ExecutionMode = cmdReq.ExecutionMode,
                TimeoutSeconds = cmdReq.TimeoutSeconds
            });
            await db.SaveChangesAsync();

            // Only after the row is committed: a waiter woken any earlier would re-query, find
            // nothing, and park again - turning the fast path into the slow one.
            notifier.Notify(cmdReq.MachineId);

            return Results.Ok(new { message = "Command queued.", commandId = cmdReq.CommandId });
        });

        app.MapGet("/api/commands/results/{commandId}", async (HttpRequest request, string commandId, RemotePulseContext db) =>
        {
            if (!request.Headers.TryGetValue("X-App-Id", out var appIdValues))
            {
                return Results.Json(new { error = "Missing X-App-Id header." }, statusCode: StatusCodes.Status401Unauthorized);
            }
            string appId = appIdValues.First() ?? string.Empty;

            (bool isValid, AuthFailureReason reason, string? error) = await VerifyAppRequestAsync(request, appId, db);
            if (!isValid)
            {
                return AuthFailureResult(reason, error);
            }

            var result = await db.CommandResults.FirstOrDefaultAsync(r => r.CommandId == commandId);
            if (result != null)
            {
                // Enforce authorization: only an App that is paired with this machine can retrieve the result
                if (string.IsNullOrEmpty(result.MachineId))
                {
                    return Results.NotFound();
                }

                bool isAuthorized = await db.Pairings.AnyAsync(p => p.AppId == appId && p.MachineId == result.MachineId && p.IsLocked);
                if (!isAuthorized)
                {
                    return Results.Json(new { error = "App is not authorized to access results for this machine." }, statusCode: StatusCodes.Status403Forbidden);
                }

                return Results.Ok(new CommandResult(
                    CommandId: result.CommandId,
                    Success: result.Success,
                    DurationMs: result.DurationMs,
                    IsEncrypted: result.IsEncrypted,
                    EncryptedPayload: result.EncryptedPayload,
                    RejectionReason: result.RejectionReason));
            }
            return Results.NotFound("Result not ready yet.");
        });

        // Unauthenticated liveness probe for deploy scripts/monitoring. Kept at this exact path
        // (rather than e.g. /api/health) because the deploy scripts and the operations docs
        // already use it - it used to be served, by coincidence, by
        // the now-removed legacy-handshake /api/pairing/status/{appId} endpoint matching
        // appId="health" (which always resolved to no pairing, i.e. {"isLocked":false}). This is
        // now a real, dedicated endpoint rather than an accidental side effect of that route.
        // The version comes from the HubServer .csproj <Version>, so "what is live" checks can
        // trust it (it used to be a hard-coded literal). Any "+<commit>" suffix the SDK appends to
        // the informational version is dropped.
        string hubVersion = (typeof(Program).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? "unknown").Split('+')[0];
        app.MapGet("/api/pairing/status/health", () => Results.Ok(new { status = "ok", isLocked = false, version = hubVersion }));

        // Watchdog feed for the App: liveness of every machine this App is paired with, in one
        // request regardless of how many that is. The machine list is derived from the App's own
        // locked pairings, so this can only ever disclose machines it's already paired with -
        // no separate ownership check is needed the way /api/commands/queue needs one.
        app.MapGet("/api/clients/status", async (HttpRequest request, RemotePulseContext db) =>
        {
            if (!request.Headers.TryGetValue("X-App-Id", out var appIdValues))
            {
                return Results.BadRequest("Missing X-App-Id header.");
            }
            string appId = appIdValues.First() ?? string.Empty;

            (bool isValid, AuthFailureReason reason, string? error) = await VerifyAppRequestAsync(request, appId, db);
            if (!isValid)
            {
                return AuthFailureResult(reason, error);
            }

            List<string> machineIds = await db.Pairings
                .Where(p => p.AppId == appId && p.IsLocked)
                .Select(p => p.MachineId)
                .ToListAsync();

            List<Client> clients = await db.Clients
                .Where(c => machineIds.Contains(c.MachineId))
                .ToListAsync();

            DateTime now = DateTime.UtcNow;
            var statuses = clients.Select(c =>
            {
                var (health, missedPolls) = EvaluateHealth(c.LastSeenUtc, c.PollIntervalSeconds, now);
                return new ClientStatus(
                    c.MachineId,
                    c.LastSeenUtc,
                    c.LastSeenUtc == null ? null : (now - c.LastSeenUtc.Value).TotalSeconds,
                    health,
                    missedPolls,
                    WorkerVersion: c.WorkerVersion,
                    Capabilities: WorkerReportedInfo.SplitCapabilities(c.WorkerCapabilities));
            }).ToList();

            return Results.Ok(statuses);
        });

        app.MapPost("/api/telemetry/logs", async (HttpRequest request, List<TelemetryLogEntry> entries, RemotePulseContext db) =>
        {
            if (entries == null || entries.Count == 0)
            {
                return Results.BadRequest(new { error = "No log entries provided." });
            }

            if (entries.Count > 50)
            {
                return Results.BadRequest(new { error = "Batch size exceeds maximum limit of 50 entries." });
            }

            // Authenticate caller (Worker or App)
            string callerSource;
            string? callerMachineId = null;
            string? callerAppId = null;

            if (request.Headers.TryGetValue("X-Client-Id", out var clientIdValues) && !string.IsNullOrWhiteSpace(clientIdValues.FirstOrDefault()))
            {
                callerMachineId = clientIdValues.First();
                var (isValid, reason, error) = await VerifyClientRequestAsync(request, callerMachineId, db);
                if (!isValid)
                {
                    return AuthFailureResult(reason, $"Client authentication failed: {error}");
                }
                callerSource = "Worker";
            }
            else if (request.Headers.TryGetValue("X-App-Id", out var appIdValues) && !string.IsNullOrWhiteSpace(appIdValues.FirstOrDefault()))
            {
                callerAppId = appIdValues.First();
                var (isValid, reason, error) = await VerifyAppRequestAsync(request, callerAppId, db);
                if (!isValid)
                {
                    return AuthFailureResult(reason, $"App authentication failed: {error}");
                }
                callerSource = "App";
            }
            else
            {
                return Results.Json(new { error = "Authentication required: missing X-Client-Id or X-App-Id signature headers." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            DateTime now = DateTime.UtcNow;
            var entities = new List<SystemLogEntity>(entries.Count);

            foreach (var entry in entries)
            {
                string logLevel = string.IsNullOrWhiteSpace(entry.LogLevel) ? "Information" : entry.LogLevel.Trim();
                if (logLevel.Length > 16) logLevel = logLevel[..16];

                string category = string.IsNullOrWhiteSpace(entry.Category) ? "General" : entry.Category.Trim();
                if (category.Length > 64) category = category[..64];

                string eventName = string.IsNullOrWhiteSpace(entry.EventName) ? "Log" : entry.EventName.Trim();
                if (eventName.Length > 64) eventName = eventName[..64];

                string message = SanitizeTelemetryText(entry.Message);

                string? dataJson = entry.DataJson;
                if (!string.IsNullOrWhiteSpace(dataJson))
                {
                    try
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(dataJson);
                        // Valid JSON payload: enforce reasonable size limit
                        if (dataJson.Length > 65536)
                        {
                            dataJson = System.Text.Json.JsonSerializer.Serialize(new { truncated = true, originalBytes = dataJson.Length });
                        }
                    }
                    catch
                    {
                        var safe = SanitizeTelemetryText(dataJson);
                        dataJson = System.Text.Json.JsonSerializer.Serialize(new { raw = safe.Length > 4096 ? safe[..4096] : safe });
                    }
                }

                entities.Add(new SystemLogEntity
                {
                    Timestamp = entry.Timestamp == default ? now : entry.Timestamp,
                    Source = callerSource,
                    MachineId = callerMachineId ?? entry.MachineId,
                    AppId = callerAppId ?? entry.AppId,
                    LogLevel = logLevel,
                    Category = category,
                    EventName = eventName,
                    Message = message,
                    DataJson = dataJson
                });
            }

            db.SystemLogs.AddRange(entities);
            await db.SaveChangesAsync();

            return Results.Ok(new { message = "Logs ingested.", count = entities.Count });
        });

        // Deliberately unauthenticated: the whole point is this has to work when a machine has
        // no signed identity yet - e.g. an Installer.ps1 failure before pairing, or a report from
        // the public portal page. Guardrails are server-side size/length caps here, psrun's
        // 32 KB body cap in Caddy (container/psrun/Caddyfile), and the tight
        // "SupportReportRateLimit" policy above - not a signature check. Stored into the existing SystemLogs table (Source prefixed
        // "SupportReport:") rather than a new table, so it shows up in /ops's log viewer for free.
        app.MapPost("/api/support/report", async (SupportReportRequest report, RemotePulseContext db) =>
        {
            if (report is null || string.IsNullOrWhiteSpace(report.Message))
            {
                return Results.BadRequest(new { error = "Message is required." });
            }

            string source = report.Source?.Trim() is "Installer" or "Web" ? report.Source!.Trim() : "Unknown";

            string message = SanitizeTelemetryText(report.Message);
            if (message.Length > 500) message = message[..500];
            if (string.IsNullOrWhiteSpace(message))
            {
                return Results.BadRequest(new { error = "Message is required." });
            }

            string? machineId = string.IsNullOrWhiteSpace(report.MachineId) ? null : report.MachineId.Trim();
            if (machineId is { Length: > 128 }) machineId = machineId[..128];

            object? detailsValue = null;
            if (!string.IsNullOrWhiteSpace(report.DetailsJson))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(report.DetailsJson);
                    // Clone so the element survives past this 'using' block's disposal.
                    detailsValue = doc.RootElement.Clone();
                }
                catch
                {
                    string safe = SanitizeTelemetryText(report.DetailsJson);
                    detailsValue = new { raw = safe.Length > 2048 ? safe[..2048] : safe };
                }
            }

            // No client IP: the report is anonymous on purpose, and an IP is personal data the
            // Hub has no use for once the request is answered (rate limiting is in memory only).
            string dataJson = System.Text.Json.JsonSerializer.Serialize(new { details = detailsValue });
            if (dataJson.Length > 8192)
            {
                dataJson = System.Text.Json.JsonSerializer.Serialize(new { truncated = true });
            }

            // A caller that knows its own severity (e.g. a successful-install confirmation from
            // the same Installer source that otherwise defaults to "Error") should say so
            // explicitly rather than be stuck with the Source-based guess below. Still an
            // allow-list, not raw client input - this ends up as a LogLevel badge in /ops.
            string? requestedLevel = report.LogLevel?.Trim();
            string logLevel = requestedLevel is "Information" or "Warning" or "Error"
                ? requestedLevel
                : (source == "Installer" ? "Error" : "Information");

            var entity = new SystemLogEntity
            {
                Timestamp = DateTime.UtcNow,
                Source = $"SupportReport:{source}",
                MachineId = machineId,
                AppId = null,
                LogLevel = logLevel,
                Category = "SupportReport",
                EventName = "SupportReport",
                Message = message,
                DataJson = dataJson
            };

            db.SystemLogs.Add(entity);
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "Report received. Thank you." });
        }).RequireRateLimiting("SupportReportRateLimit");

        app.MapGet("/api/telemetry/logs", async (
            HttpRequest request,
            IConfiguration config,
            RemotePulseContext db,
            string? source,
            string? logLevel,
            string? machineId,
            string? appId,
            int? limit) =>
        {
            string? authenticatedAppId = null;
            bool isAdmin = false;

            string? configuredAdminKey = config["AdminApiKey"];
            if (!string.IsNullOrEmpty(configuredAdminKey) &&
                request.Headers.TryGetValue("X-Admin-Key", out var adminKeyValues) &&
                !string.IsNullOrEmpty(adminKeyValues.FirstOrDefault()))
            {
                byte[] a = System.Text.Encoding.UTF8.GetBytes(adminKeyValues.First()!);
                byte[] b = System.Text.Encoding.UTF8.GetBytes(configuredAdminKey);
                if (System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b))
                {
                    isAdmin = true;
                }
            }
            else if (request.Headers.TryGetValue("X-App-Id", out var appIdValues) && !string.IsNullOrWhiteSpace(appIdValues.FirstOrDefault()))
            {
                string callingAppId = appIdValues.First();
                var (isValid, reason, error) = await VerifyAppRequestAsync(request, callingAppId, db);
                if (!isValid)
                {
                    return AuthFailureResult(reason, $"App authentication failed: {error}");
                }
                authenticatedAppId = callingAppId;
            }
            else
            {
                return Results.Json(new { error = "Authentication required: valid X-App-Id signature headers or X-Admin-Key required." }, statusCode: StatusCodes.Status401Unauthorized);
            }

            int maxLimit = Math.Clamp(limit ?? 50, 1, 500);
            IQueryable<SystemLogEntity> query = db.SystemLogs.AsNoTracking();

            if (!isAdmin && authenticatedAppId != null)
            {
                var pairedMachineIds = await db.Pairings
                    .Where(p => p.AppId == authenticatedAppId && p.IsLocked)
                    .Select(p => p.MachineId)
                    .ToListAsync();

                query = query.Where(l => l.AppId == authenticatedAppId || (l.MachineId != null && pairedMachineIds.Contains(l.MachineId)));
            }

            if (!string.IsNullOrWhiteSpace(source))
            {
                query = query.Where(l => l.Source == source);
            }
            if (!string.IsNullOrWhiteSpace(logLevel))
            {
                query = query.Where(l => l.LogLevel == logLevel);
            }
            if (!string.IsNullOrWhiteSpace(machineId))
            {
                query = query.Where(l => l.MachineId == machineId);
            }
            if (!string.IsNullOrWhiteSpace(appId))
            {
                query = query.Where(l => l.AppId == appId);
            }

            var results = await query
                .OrderByDescending(l => l.Timestamp)
                .Take(maxLimit)
                .Select(l => new TelemetryLogEntry
                {
                    Timestamp = l.Timestamp,
                    Source = l.Source,
                    MachineId = l.MachineId,
                    AppId = l.AppId,
                    LogLevel = l.LogLevel,
                    Category = l.Category,
                    EventName = l.EventName,
                    Message = l.Message,
                    DataJson = l.DataJson
                })
                .ToListAsync();

            return Results.Ok(results);
        });

        string? configuredAdminToken = app.Configuration["ADMIN_TOKEN"] ?? app.Configuration["RemotePulse:AdminToken"];

        bool IsAdminAuthorized(HttpContext context)
        {
            if (string.IsNullOrWhiteSpace(configuredAdminToken))
            {
                return false;
            }

            if (context.Request.Headers.TryGetValue("X-Admin-Token", out var headerVal) &&
                CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(headerVal.ToString()),
                    Encoding.UTF8.GetBytes(configuredAdminToken)))
            {
                return true;
            }

            if (context.Request.Query.TryGetValue("token", out var queryVal) &&
                CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(queryVal.ToString()),
                    Encoding.UTF8.GetBytes(configuredAdminToken)))
            {
                return true;
            }

            return false;
        }

        async Task<OpsDashboardData> GetOpsDashboardDataAsync(RemotePulseContext db, IHostEnvironment env)
        {
            var nowUtc = DateTime.UtcNow;
            var clients = await db.Clients.AsNoTracking().ToListAsync();
            var pairings = await db.Pairings.AsNoTracking().ToListAsync();

            var clientSummaries = clients.Select(c =>
            {
                var (health, missed) = EvaluateHealth(c.LastSeenUtc, c.PollIntervalSeconds, nowUtc);
                double? ageSeconds = c.LastSeenUtc.HasValue ? Math.Round((nowUtc - c.LastSeenUtc.Value).TotalSeconds, 1) : null;
                var pairedApps = pairings.Where(p => p.MachineId == c.MachineId).Select(p => p.AppId).ToList();
                return new OpsClientInfo
                {
                    MachineId = c.MachineId,
                    Health = health.ToString(),
                    MissedPolls = missed,
                    LastSeenUtc = c.LastSeenUtc,
                    AgeSeconds = ageSeconds,
                    PollIntervalSeconds = c.PollIntervalSeconds ?? DefaultPollIntervalSeconds,
                    PairedApps = pairedApps
                };
            }).OrderByDescending(c => c.LastSeenUtc).ToList();

            var oneHourAgo = nowUtc.AddHours(-1);
            var oneDayAgo = nowUtc.AddHours(-24);
            var sevenDaysAgo = nowUtc.AddDays(-7);

            var totalCommands = await db.CommandResults.CountAsync();
            var commands7dList = await db.CommandResults
                .AsNoTracking()
                .Where(r => r.DateCreated >= sevenDaysAgo)
                .Select(r => new { r.DateCreated, r.Success, r.DurationMs })
                .ToListAsync();

            int last7Days = commands7dList.Count;
            int last24Hours = commands7dList.Count(r => r.DateCreated >= oneDayAgo);
            int last1Hour = commands7dList.Count(r => r.DateCreated >= oneHourAgo);
            int successful = commands7dList.Count(r => r.Success);
            int failed = commands7dList.Count(r => !r.Success);
            double avgDuration = commands7dList.Count > 0 ? Math.Round(commands7dList.Average(r => r.DurationMs), 1) : 0;

            var recentCommands = await db.CommandResults
                .AsNoTracking()
                .OrderByDescending(r => r.DateCreated)
                .Take(20)
                .Select(r => new OpsCommandResult
                {
                    CommandId = r.CommandId,
                    MachineId = r.MachineId,
                    AppId = r.AppId,
                    Success = r.Success,
                    DurationMs = Math.Round(r.DurationMs, 1),
                    DateCreated = r.DateCreated,
                    OutputSnippet = r.IsEncrypted ? "[Encrypted Output]" : (r.RejectionReason ?? string.Empty)
                })
                .ToListAsync();

            var recentLogs = await db.SystemLogs
                .AsNoTracking()
                .OrderByDescending(l => l.Timestamp)
                .Take(50)
                .Select(l => new OpsSystemLog
                {
                    Id = l.Id,
                    Timestamp = l.Timestamp,
                    LogLevel = l.LogLevel,
                    Source = l.Source,
                    MachineId = l.MachineId,
                    Category = l.Category,
                    EventName = l.EventName,
                    Message = l.Message
                })
                .ToListAsync();

            return new OpsDashboardData
            {
                ServerTimeUtc = nowUtc,
                Environment = env.EnvironmentName,
                Clients = clientSummaries,
                Throughput = new OpsThroughputInfo
                {
                    TotalCommands = totalCommands,
                    Last1Hour = last1Hour,
                    Last24Hours = last24Hours,
                    Last7Days = last7Days,
                    Successful = successful,
                    Failed = failed,
                    AvgDurationMs = avgDuration
                },
                RecentCommands = recentCommands,
                RecentLogs = recentLogs
            };
        }

        app.MapGet("/ops/metrics", async (HttpContext context, RemotePulseContext db, IHostEnvironment env) =>
        {
            if (!IsAdminAuthorized(context))
            {
                return Results.Unauthorized();
            }

            var data = await GetOpsDashboardDataAsync(db, env);
            return Results.Ok(data);
        });

        app.MapGet("/ops", async (HttpContext context, RemotePulseContext db, IHostEnvironment env) =>
        {
            if (!IsAdminAuthorized(context))
            {
                string message = string.IsNullOrWhiteSpace(configuredAdminToken)
                    ? "ADMIN_TOKEN is not configured on this server. Configure ADMIN_TOKEN in the environment to enable the dashboard."
                    : "Access requires a valid admin token. Append ?token=YOUR_TOKEN or enter it below.";

                return Results.Text(
                    $@"<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>401 Unauthorized - RemotePulse Ops</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        div {{ background: #161b22; padding: 2rem; border-radius: 8px; border: 1px solid #30363d; max-width: 420px; width: 90%; text-align: center; }}
        h2 {{ color: #f85149; margin-top: 0; font-size: 1.3rem; }}
        p {{ color: #8b949e; font-size: 0.9rem; margin-top: 0.5rem; line-height: 1.4; }}
        input {{ width: 100%; padding: 0.6rem 0.8rem; margin-top: 1rem; box-sizing: border-box; border-radius: 6px; border: 1px solid #30363d; background: #0d1117; color: #fff; font-size: 0.9rem; }}
        input:focus {{ outline: none; border-color: #58a6ff; }}
        button {{ margin-top: 1rem; width: 100%; padding: 0.6rem; background: #238636; color: #fff; border: 1px solid rgba(240, 246, 252, 0.1); border-radius: 6px; font-weight: 600; cursor: pointer; }}
        button:hover {{ background: #2ea043; }}
    </style>
</head>
<body>
    <div>
        <h2>401 Unauthorized</h2>
        <p>{WebUtility.HtmlEncode(message)}</p>
        <form method=""GET"">
            <input type=""password"" name=""token"" placeholder=""Enter ADMIN_TOKEN"" autofocus required />
            <button type=""submit"">Authenticate &amp; Open Ops</button>
        </form>
    </div>
</body>
</html>",
                    contentType: "text/html",
                    statusCode: 401);
            }

            string token = context.Request.Query.TryGetValue("token", out var qToken)
                ? qToken.ToString()
                : (context.Request.Headers.TryGetValue("X-Admin-Token", out var hToken) ? hToken.ToString() : "");

            var data = await GetOpsDashboardDataAsync(db, env);
            string html = OpsDashboardRenderer.RenderHtml(data, token);
            return Results.Content(html, "text/html");
        });

        app.MapGet("/", (IHostEnvironment env) =>
        {
            return Results.Ok(new
            {
                service = "InspiredCodes RemotePulse Hub Server",
                status = "Online",
                environment = env.EnvironmentName,
                time = DateTime.UtcNow
            });
        });

        await app.RunAsync();
    }
}


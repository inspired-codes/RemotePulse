using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using InspiredCodes.RemotePulse.HubServer.Data;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using Xunit;

namespace InspiredCodes.RemotePulse.HubServer.IntegrationTests;

/// <summary>
/// Covers POST /api/pairing/v2, the Pairing v2 key-bound co-presence registration+pairing
/// endpoint described in docs/specs/pairing-v2-key-binding-spec.md. Both the Worker and the
/// Mobile App submit the HKDF-derived <c>PairingId</c> (never the raw secret <c>S</c>); the
/// Hub matches on <c>PairingId</c>, stores <c>AppBindTag</c>, and emits the 5-part
/// <c>PAIRING:&lt;AppId&gt;:&lt;AppPublicKey&gt;:&lt;pid&gt;:&lt;AppBindTag&gt;</c> announcement.
/// </summary>
public class CoPresencePairingTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _httpClient;
    private readonly string _tempKeyPath;
    private readonly KeyPairManager _keyManager;

    public CoPresencePairingTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", "InMemory_CoPresencePairingTests" },
                    { "RateLimiting:PairingPermitsPerMinute", "1000" }
                });
            });
        });
        _httpClient = _factory.CreateClient();
        _tempKeyPath = Path.Combine(Path.GetTempPath(), $"copresence_int_test_{Guid.NewGuid():N}.dat");
        _keyManager = new KeyPairManager(_tempKeyPath);
        _keyManager.GenerateAndSaveKeys();
    }

    [Fact]
    public async Task RetiredPairingV1Endpoint_ShouldReturnNotFound()
    {
        var response = await _httpClient.PostAsJsonAsync("/api/pairing/v1", new { });
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ClientThenApp_MatchingPairingId_ShouldRegisterClientStoreBindTagAndEmit5PartAnnouncement()
    {
        string secret = PairingCrypto.GenerateSecret();
        string pairingId = PairingCrypto.DerivePairingId(secret);
        string machineId = Guid.NewGuid().ToString();
        string appId = Guid.NewGuid().ToString();
        string clientPublicKey = _keyManager.GetPublicKeyBase64();
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(clientPublicKey);
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPublicKey = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());
        string appBindTag = PairingCrypto.ComputeAppBindTag(secret, pairingId, workerFp, appId, appPublicKey);

        var clientSubmission = new CoPresenceSubmission(pairingId, "Client", DateTimeOffset.UtcNow, MachineId: machineId, PublicKey: clientPublicKey);
        var clientResponse = await _httpClient.PostAsJsonAsync("/api/pairing/v2", clientSubmission);
        Assert.Equal(HttpStatusCode.OK, clientResponse.StatusCode);

        // Not matched yet - the Client submission alone shouldn't have registered anything.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            Assert.False(await db.Clients.AnyAsync(c => c.MachineId == machineId));
        }

        var appSubmission = new CoPresenceSubmission(
            PairingId: pairingId,
            Role: "App",
            GeneratedAtUtc: DateTimeOffset.UtcNow,
            AppId: appId,
            AppPublicKey: appPublicKey,
            SecretSignature: SignPairingId(appEcdsa, pairingId),
            AppBindTag: appBindTag);
        var appResponse = await _httpClient.PostAsJsonAsync("/api/pairing/v2", appSubmission);
        Assert.Equal(HttpStatusCode.OK, appResponse.StatusCode);

        using var matchDoc = JsonDocument.Parse(await appResponse.Content.ReadAsStringAsync());
        Assert.Equal(clientPublicKey, matchDoc.RootElement.GetProperty("clientPublicKey").GetString());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();

            var client = await db.Clients.FirstOrDefaultAsync(c => c.MachineId == machineId);
            Assert.NotNull(client);
            Assert.Equal(clientPublicKey, client!.PublicKey);

            var pairing = await db.Pairings.FirstOrDefaultAsync(p => p.MachineId == machineId && p.AppId == appId);
            Assert.NotNull(pairing);
            Assert.True(pairing!.IsLocked);
            Assert.Equal(appPublicKey, pairing.AppPublicKey);
            Assert.Equal(pairingId, pairing.PairingId);
            Assert.Equal(appBindTag, pairing.AppBindTag);
            Assert.Null(pairing.AnnouncedToClientAtUtc);

            // The pending ticket is consumed once matched, not left lingering.
            Assert.False(await db.PendingCoPresences.AnyAsync(p => p.PairingId == pairingId));
        }

        // The Worker learns the App's public key, pid, and AppBindTag via its next poll in the 5-part announcement.
        using var pollRequest = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddClientSignatureHeaders(pollRequest, machineId, _keyManager);
        var pollResponse = await _httpClient.SendAsync(pollRequest);
        Assert.Equal(HttpStatusCode.OK, pollResponse.StatusCode);

        var announcement = await pollResponse.Content.ReadFromJsonAsync<ServerCommand>(JsonOptions);
        Assert.NotNull(announcement);
        Assert.Equal("PAIRING-ANNOUNCE", announcement!.CommandId);
        Assert.Equal($"PAIRING:{appId}:{appPublicKey}:{pairingId}:{appBindTag}", announcement.Script);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            var pairing = await db.Pairings.SingleAsync(p => p.MachineId == machineId && p.AppId == appId);
            Assert.NotNull(pairing.AnnouncedToClientAtUtc);
        }

        // A second poll shouldn't re-announce the same pairing forever.
        using var secondPollRequest = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddClientSignatureHeaders(secondPollRequest, machineId, _keyManager);
        var secondPollResponse = await _httpClient.SendAsync(secondPollRequest);
        Assert.Equal(HttpStatusCode.NoContent, secondPollResponse.StatusCode);
    }

    [Fact]
    public async Task RePairingSameApp_UpdateBranch_StoresUpdatedPairingIdAndAppBindTagAndReAnnounces()
    {
        string machineId = Guid.NewGuid().ToString();
        string appId = Guid.NewGuid().ToString();
        string clientPublicKey = _keyManager.GetPublicKeyBase64();
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(clientPublicKey);

        // 1. Initial pairing (insert branch)
        string secret1 = PairingCrypto.GenerateSecret();
        string pid1 = PairingCrypto.DerivePairingId(secret1);
        using var appEcdsa1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appKey1 = Convert.ToBase64String(appEcdsa1.ExportSubjectPublicKeyInfo());
        string tag1 = PairingCrypto.ComputeAppBindTag(secret1, pid1, workerFp, appId, appKey1);

        await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid1, "Client", DateTimeOffset.UtcNow, MachineId: machineId, PublicKey: clientPublicKey));
        var r1 = await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid1, "App", DateTimeOffset.UtcNow, AppId: appId, AppPublicKey: appKey1, SecretSignature: SignPairingId(appEcdsa1, pid1), AppBindTag: tag1));
        Assert.Equal(HttpStatusCode.OK, r1.StatusCode);

        // Consume first announcement
        using (var poll1 = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll"))
        {
            AddClientSignatureHeaders(poll1, machineId, _keyManager);
            var poll1Resp = await _httpClient.SendAsync(poll1);
            Assert.Equal(HttpStatusCode.OK, poll1Resp.StatusCode);
        }

        // 2. Re-pair same AppId without prior /api/pairing/release (exercises existingPairing != null update branch)
        string secret2 = PairingCrypto.GenerateSecret();
        string pid2 = PairingCrypto.DerivePairingId(secret2);
        using var appEcdsa2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appKey2 = Convert.ToBase64String(appEcdsa2.ExportSubjectPublicKeyInfo());
        string tag2 = PairingCrypto.ComputeAppBindTag(secret2, pid2, workerFp, appId, appKey2);

        await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid2, "Client", DateTimeOffset.UtcNow, MachineId: machineId, PublicKey: clientPublicKey));
        var r2 = await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid2, "App", DateTimeOffset.UtcNow, AppId: appId, AppPublicKey: appKey2, SecretSignature: SignPairingId(appEcdsa2, pid2), AppBindTag: tag2));
        Assert.Equal(HttpStatusCode.OK, r2.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            var pairing = await db.Pairings.SingleAsync(p => p.MachineId == machineId && p.AppId == appId);
            Assert.Equal(appKey2, pairing.AppPublicKey);
            Assert.Equal(pid2, pairing.PairingId);
            Assert.Equal(tag2, pairing.AppBindTag);
            Assert.Null(pairing.AnnouncedToClientAtUtc);
        }

        // Verify the 5-part announcement carries the new pid2 and tag2
        using var poll2 = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddClientSignatureHeaders(poll2, machineId, _keyManager);
        var poll2Resp = await _httpClient.SendAsync(poll2);
        Assert.Equal(HttpStatusCode.OK, poll2Resp.StatusCode);
        var announcement2 = await poll2Resp.Content.ReadFromJsonAsync<ServerCommand>(JsonOptions);
        Assert.NotNull(announcement2);
        Assert.Equal($"PAIRING:{appId}:{appKey2}:{pid2}:{tag2}", announcement2!.Script);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")] // '=' not allowed in base64url
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+")] // '+' not allowed in base64url
    public async Task App_MissingOrMalformedAppBindTag_ShouldReturnBadRequest(string? badTag)
    {
        string pid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        string machineId = Guid.NewGuid().ToString();
        await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid, "Client", DateTimeOffset.UtcNow, MachineId: machineId, PublicKey: _keyManager.GetPublicKeyBase64()));

        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPublicKey = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());
        var appSub = new CoPresenceSubmission(
            PairingId: pid,
            Role: "App",
            GeneratedAtUtc: DateTimeOffset.UtcNow,
            AppId: Guid.NewGuid().ToString(),
            AppPublicKey: appPublicKey,
            SecretSignature: SignPairingId(appEcdsa, pid),
            AppBindTag: badTag);

        var response = await _httpClient.PostAsJsonAsync("/api/pairing/v2", appSub);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// Produces the SEC-6 proof-of-possession signature an App submission must carry: an ECDSA
    /// signature over the UTF-8 bytes of the <c>PairingId</c> (<c>pid</c>), made with the App's
    /// own private key.
    /// </summary>
    private static string SignPairingId(ECDsa appEcdsa, string pairingId)
    {
        byte[] signature = appEcdsa.SignData(
            Encoding.UTF8.GetBytes(pairingId),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Convert.ToBase64String(signature);
    }

    private static void AddClientSignatureHeaders(HttpRequestMessage request, string machineId, KeyPairManager keyManager)
    {
        string nonce = Guid.NewGuid().ToString("N");
        string timestamp = DateTimeOffset.UtcNow.ToString("o");
        string method = request.Method.Method.ToUpperInvariant();
        string path = "/";
        if (request.RequestUri != null)
        {
            if (request.RequestUri.IsAbsoluteUri)
            {
                path = request.RequestUri.AbsolutePath;
            }
            else
            {
                string raw = request.RequestUri.OriginalString;
                int q = raw.IndexOf('?');
                path = q >= 0 ? raw.Substring(0, q) : raw;
                if (!path.StartsWith('/'))
                {
                    path = "/" + path;
                }
            }
        }
        string message = $"{method}:{path}:{machineId}:{timestamp}:{nonce}";
        byte[] signature = keyManager.SignData(Encoding.UTF8.GetBytes(message));

        request.Headers.Add("X-Client-Id", machineId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Signature", Convert.ToBase64String(signature));
    }

    [Fact]
    public async Task App_UnknownPairingId_ShouldReturnNotFound()
    {
        string pid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        var appSubmission = new CoPresenceSubmission(
            PairingId: pid,
            Role: "App",
            GeneratedAtUtc: DateTimeOffset.UtcNow,
            AppId: Guid.NewGuid().ToString(),
            AppPublicKey: "whatever",
            AppBindTag: PairingCrypto.GenerateSecret());

        var response = await _httpClient.PostAsJsonAsync("/api/pairing/v2", appSubmission);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task App_ExpiredPairingId_ShouldReturnGoneAndCleanUpTheTicket()
    {
        string pid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        string machineId = Guid.NewGuid().ToString();

        // Seed an already-expired ticket directly, rather than sleeping past a real 90s window.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.PendingCoPresences.Add(new PendingCoPresence
            {
                PairingId = pid,
                ClientMachineId = machineId,
                ClientPublicKey = _keyManager.GetPublicKeyBase64(),
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1)
            });
            await db.SaveChangesAsync();
        }

        var appSubmission = new CoPresenceSubmission(
            PairingId: pid,
            Role: "App",
            GeneratedAtUtc: DateTimeOffset.UtcNow,
            AppId: Guid.NewGuid().ToString(),
            AppPublicKey: "whatever",
            AppBindTag: PairingCrypto.GenerateSecret());
        var response = await _httpClient.PostAsJsonAsync("/api/pairing/v2", appSubmission);

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            Assert.False(await db.PendingCoPresences.AnyAsync(p => p.PairingId == pid));
            Assert.False(await db.Clients.AnyAsync(c => c.MachineId == machineId));
        }
    }

    [Fact]
    public async Task Match_ForMachineIdAlreadyClaimedByADifferentKey_ShouldBeRejectedAndNotOverwrite()
    {
        string machineId = Guid.NewGuid().ToString();
        string originalPublicKey = _keyManager.GetPublicKeyBase64();
        string validTag = PairingCrypto.GenerateSecret();

        // First, a legitimate match establishes the machine's identity.
        string pid1 = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        using var app1Ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appKey1 = Convert.ToBase64String(app1Ecdsa.ExportSubjectPublicKeyInfo());
        await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid1, "Client", DateTimeOffset.UtcNow, MachineId: machineId, PublicKey: originalPublicKey));
        await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid1, "App", DateTimeOffset.UtcNow, AppId: Guid.NewGuid().ToString(), AppPublicKey: appKey1, SecretSignature: SignPairingId(app1Ecdsa, pid1), AppBindTag: validTag));

        // Now someone (or something) tries to re-claim the same MachineId with a different key.
        using KeyPairManager impostorKeyManager = new KeyPairManager(Path.Combine(Path.GetTempPath(), $"copresence_impostor_{Guid.NewGuid():N}.dat"));
        impostorKeyManager.GenerateAndSaveKeys();
        string impostorPublicKey = impostorKeyManager.GetPublicKeyBase64();

        string pid2 = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        using var app2Ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appKey2 = Convert.ToBase64String(app2Ecdsa.ExportSubjectPublicKeyInfo());
        await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid2, "Client", DateTimeOffset.UtcNow, MachineId: machineId, PublicKey: impostorPublicKey));
        var conflictResponse = await _httpClient.PostAsJsonAsync("/api/pairing/v2",
            new CoPresenceSubmission(pid2, "App", DateTimeOffset.UtcNow, AppId: Guid.NewGuid().ToString(), AppPublicKey: appKey2, SecretSignature: SignPairingId(app2Ecdsa, pid2), AppBindTag: validTag));

        Assert.Equal(HttpStatusCode.Conflict, conflictResponse.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();

            // The originally-registered key must survive the attempted hijack untouched.
            var client = await db.Clients.SingleAsync(c => c.MachineId == machineId);
            Assert.Equal(originalPublicKey, client.PublicKey);

            // The spent (rejected) ticket doesn't linger either.
            Assert.False(await db.PendingCoPresences.AnyAsync(p => p.PairingId == pid2));
        }
    }

    [Fact]
    public async Task InvalidRole_ShouldReturnBadRequest()
    {
        string pid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        var submission = new CoPresenceSubmission(pid, "NotARealRole", DateTimeOffset.UtcNow);

        var response = await _httpClient.PostAsJsonAsync("/api/pairing/v2", submission);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task WorkerUrl_To_AppParser_To_HubPairing_RoundTrip_ShouldSucceed()
    {
        // 1. Worker generates secret S, derives pid and fp, and forms the Pairing v2 QR URL
        string secret = PairingCrypto.GenerateSecret();
        string pid = PairingCrypto.DerivePairingId(secret);
        string workerPubKey = _keyManager.GetPublicKeyBase64();
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(workerPubKey);
        var generatedAt = DateTimeOffset.UtcNow;
        string hubUrl = "https://rmpls.inspired.codes:8443";
        string fragment = $"k={Uri.EscapeDataString(secret)}&fp={Uri.EscapeDataString(workerFp)}&ts={Uri.EscapeDataString(generatedAt.ToString("o"))}";
        string workerQrUrl = $"{hubUrl}/pairing/v2#{fragment}";

        // Worker submits its role to Hub with pid (never S)
        string machineId = $"machine-{Guid.NewGuid():N}";
        var workerSubmission = new CoPresenceSubmission(
            pid,
            "Client",
            generatedAt,
            MachineId: machineId,
            PublicKey: workerPubKey);

        var workerResponse = await _httpClient.PostAsJsonAsync("/api/pairing/v2", workerSubmission);
        Assert.Equal(HttpStatusCode.OK, workerResponse.StatusCode);

        // 2. Mobile App scans the raw QR text and decodes with PairingLinkParser
        bool parsed = InspiredCodes.RemotePulse.App.Services.PairingLinkParser.TryParse(workerQrUrl, out var parsedLink);
        Assert.True(parsed);
        Assert.NotNull(parsedLink);
        Assert.Equal(2, parsedLink.Version);
        Assert.Equal(secret, parsedLink.Secret);
        Assert.Equal(workerFp, parsedLink.WorkerFingerprint);
        Assert.Equal(generatedAt, parsedLink.GeneratedAtUtc);
        Assert.Equal(hubUrl, parsedLink.HubOrigin);

        // 3. Mobile App derives pid and AppBindTag from parsedLink and submits to Hub
        string appId = $"app-{Guid.NewGuid():N}";
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPublicKey = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());
        string appPid = PairingCrypto.DerivePairingId(parsedLink.Secret);
        string appBindTag = PairingCrypto.ComputeAppBindTag(parsedLink.Secret, appPid, parsedLink.WorkerFingerprint!, appId, appPublicKey);

        var appSubmission = new CoPresenceSubmission(
            appPid,
            "App",
            parsedLink.GeneratedAtUtc,
            AppId: appId,
            AppPublicKey: appPublicKey,
            SecretSignature: SignPairingId(appEcdsa, appPid),
            AppBindTag: appBindTag);

        var appResponse = await _httpClient.PostAsJsonAsync("/api/pairing/v2", appSubmission);
        Assert.Equal(HttpStatusCode.OK, appResponse.StatusCode);

        using var matchDoc = JsonDocument.Parse(await appResponse.Content.ReadAsStringAsync());
        string returnedWorkerKey = matchDoc.RootElement.GetProperty("clientPublicKey").GetString()!;
        Assert.Equal(workerPubKey, returnedWorkerKey);
        Assert.True(PairingCrypto.VerifyPublicKeyFingerprint(returnedWorkerKey, parsedLink.WorkerFingerprint));

        // 4. Assert Pairing is locked on Hub with matched MachineId, AppId, PairingId, and AppBindTag
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();

        var pairing = await db.Pairings.SingleOrDefaultAsync(p => p.MachineId == machineId && p.AppId == appId);
        Assert.NotNull(pairing);
        Assert.True(pairing.IsLocked);
        Assert.Equal(appPublicKey, pairing.AppPublicKey);
        Assert.Equal(pid, pairing.PairingId);
        Assert.Equal(appBindTag, pairing.AppBindTag);

        var client = await db.Clients.SingleOrDefaultAsync(c => c.MachineId == machineId);
        Assert.NotNull(client);
        Assert.Equal(workerPubKey, client.PublicKey);
    }

    [Fact]
    public async Task CoPresence_OversizedPairingId_ShouldReturnBadRequest()
    {
        var submission = new
        {
            PairingId = new string('A', 5000),
            Role = "Client",
            MachineId = "TEST-MACHINE",
            PublicKey = "key"
        };

        var response = await _httpClient.PostAsJsonAsync("/api/pairing/v2", submission);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task CoPresencePairing_RateLimit_EleventhCallReturns429Async()
    {
        var factory = _factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", "InMemoryRateLimit" },
                    { "RateLimiting:PairingPermitsPerMinute", "10" }
                });
            });
        });
        using var client = factory.CreateClient();
        // TestServer has no peer address, and requests without one are never rate limited.
        // A forwarded client IP gives the limiter a real partition, as Caddy's header does live.
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.7");

        string validPid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        for (int i = 0; i < 10; i++)
        {
            var submission = new
            {
                PairingId = validPid,
                Role = "Client",
                GeneratedAtUtc = DateTimeOffset.UtcNow,
                MachineId = $"machine-{i}",
                PublicKey = "pubkey"
            };
            using var response = await client.PostAsJsonAsync("/api/pairing/v2", submission);
            Assert.True(response.StatusCode != HttpStatusCode.TooManyRequests, $"Call {i + 1} should not be rate limited.");
        }

        // 11th call should return 429
        var excessSubmission = new
        {
            PairingId = validPid,
            Role = "Client",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            MachineId = "machine-excess",
            PublicKey = "pubkey"
        };
        using var excessResponse = await client.PostAsJsonAsync("/api/pairing/v2", excessSubmission);
        Assert.Equal(HttpStatusCode.TooManyRequests, excessResponse.StatusCode);
    }

    [Fact]
    public async Task CoPresencePairing_SecretSignature_ProofOfPossessionAsync()
    {
        string pid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        string machineId = "test-m-" + Guid.NewGuid().ToString("N");
        string validTag = PairingCrypto.GenerateSecret();

        // 1. Worker submits
        var clientSub = new
        {
            PairingId = pid,
            Role = "Client",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            MachineId = machineId,
            PublicKey = _keyManager.GetPublicKeyBase64()
        };
        var r1 = await _httpClient.PostAsJsonAsync("/api/pairing/v2", clientSub);
        Assert.Equal(HttpStatusCode.OK, r1.StatusCode);

        // 2. App submits with no signature at all -> 400 Bad Request
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPubKey = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());

        var missingSigSub = new
        {
            PairingId = pid,
            Role = "App",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            AppId = "app-pop-test",
            AppPublicKey = appPubKey,
            AppBindTag = validTag
        };
        var rMissing = await _httpClient.PostAsJsonAsync("/api/pairing/v2", missingSigSub);
        Assert.Equal(HttpStatusCode.BadRequest, rMissing.StatusCode);
        string rMissingBody = await rMissing.Content.ReadAsStringAsync();
        Assert.Contains("SecretSignature is required", rMissingBody);

        // 3. App submits with forged/invalid signature -> 400 Bad Request
        string fakeSig = Convert.ToBase64String(appEcdsa.SignData(Encoding.UTF8.GetBytes("wrong-payload"), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        var invalidSub = new
        {
            PairingId = pid,
            Role = "App",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            AppId = "app-pop-test",
            AppPublicKey = appPubKey,
            SecretSignature = fakeSig,
            AppBindTag = validTag
        };
        var r2 = await _httpClient.PostAsJsonAsync("/api/pairing/v2", invalidSub);
        Assert.Equal(HttpStatusCode.BadRequest, r2.StatusCode);
        string r2Body = await r2.Content.ReadAsStringAsync();
        Assert.Contains("Invalid secret signature", r2Body);

        // 4. App submits with valid signature over UTF8(pid) -> 200 OK
        string validSig = Convert.ToBase64String(appEcdsa.SignData(Encoding.UTF8.GetBytes(pid), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var validSub = new
        {
            PairingId = pid,
            Role = "App",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            AppId = "app-pop-test",
            AppPublicKey = appPubKey,
            SecretSignature = validSig,
            AppBindTag = validTag
        };
        var r3 = await _httpClient.PostAsJsonAsync("/api/pairing/v2", validSub);
        Assert.Equal(HttpStatusCode.OK, r3.StatusCode);
    }

    [Fact]
    public async Task FinalizeCoPresence_WhenWorkerAlreadyPairedWithDifferentApp_ShouldReturn409Conflict()
    {
        string machineId = Guid.NewGuid().ToString();
        string clientPublicKey = _keyManager.GetPublicKeyBase64();
        string existingAppId = Guid.NewGuid().ToString();

        // 1. Seed existing locked pairing for this machine with existingAppId
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = machineId, PublicKey = clientPublicKey });
            db.Pairings.Add(new Pairing
            {
                MachineId = machineId,
                AppId = existingAppId,
                AppPublicKey = "EXISTING_KEY",
                IsLocked = true
            });
            await db.SaveChangesAsync();
        }

        // 2. Client submits a new co-presence PairingId
        string pid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        var clientSub = new CoPresenceSubmission(pid, "Client", DateTimeOffset.UtcNow, MachineId: machineId, PublicKey: clientPublicKey);
        var clientResp = await _httpClient.PostAsJsonAsync("/api/pairing/v2", clientSub);
        Assert.Equal(HttpStatusCode.OK, clientResp.StatusCode);

        // 3. Different App submits matching PairingId -> should return 409 Conflict
        string newAppId = Guid.NewGuid().ToString();
        using var newAppEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string newAppPubKey = Convert.ToBase64String(newAppEcdsa.ExportSubjectPublicKeyInfo());

        var appSub = new CoPresenceSubmission(
            pid,
            "App",
            DateTimeOffset.UtcNow,
            AppId: newAppId,
            AppPublicKey: newAppPubKey,
            SecretSignature: SignPairingId(newAppEcdsa, pid),
            AppBindTag: PairingCrypto.GenerateSecret());
        var appResp = await _httpClient.PostAsJsonAsync("/api/pairing/v2", appSub);
        Assert.Equal(HttpStatusCode.Conflict, appResp.StatusCode);

        string body = await appResp.Content.ReadAsStringAsync();
        Assert.Contains("This Worker is already paired with a different Mobile device", body);

        // 4. PendingCoPresence must be removed
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            Assert.False(await db.PendingCoPresences.AnyAsync(p => p.PairingId == pid));
        }
    }

    [Fact]
    public async Task ReleasePairing_SignedAndUnsigned_ShouldWorkAsExpected()
    {
        string machineId = Guid.NewGuid().ToString();
        string clientPublicKey = _keyManager.GetPublicKeyBase64();
        string appId = Guid.NewGuid().ToString();

        // 1. Seed pairing
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = machineId, PublicKey = clientPublicKey });
            db.Pairings.Add(new Pairing
            {
                MachineId = machineId,
                AppId = appId,
                AppPublicKey = "TEST_KEY",
                IsLocked = true
            });
            await db.SaveChangesAsync();
        }

        // 2. Unsigned request -> 401 Unauthorized
        var unsignedReq = new HttpRequestMessage(HttpMethod.Post, "/api/pairing/release");
        unsignedReq.Headers.Add("X-Client-Id", machineId);
        unsignedReq.Content = JsonContent.Create(new ReleasePairingRequest(appId));
        var unsignedResp = await _httpClient.SendAsync(unsignedReq);
        Assert.Equal(HttpStatusCode.Unauthorized, unsignedResp.StatusCode);

        // 3. Signed request -> 200 OK and deletes pairing
        var signedReq = new HttpRequestMessage(HttpMethod.Post, "/api/pairing/release");
        signedReq.Content = JsonContent.Create(new ReleasePairingRequest(appId));
        AddSignatureHeaders(signedReq, machineId, _keyManager);
        var signedResp = await _httpClient.SendAsync(signedReq);
        Assert.Equal(HttpStatusCode.OK, signedResp.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            Assert.False(await db.Pairings.AnyAsync(p => p.MachineId == machineId && p.AppId == appId));
        }
    }

    private static void AddSignatureHeaders(HttpRequestMessage request, string clientId, KeyPairManager keyManager)
    {
        string nonce = Guid.NewGuid().ToString("N");
        string timestamp = DateTimeOffset.UtcNow.ToString("o");
        string method = request.Method.Method.ToUpperInvariant();
        string path = "/";
        if (request.RequestUri != null)
        {
            if (request.RequestUri.IsAbsoluteUri)
            {
                path = request.RequestUri.AbsolutePath;
            }
            else
            {
                string raw = request.RequestUri.OriginalString;
                int q = raw.IndexOf('?');
                path = q >= 0 ? raw.Substring(0, q) : raw;
                if (!path.StartsWith('/'))
                {
                    path = "/" + path;
                }
            }
        }

        string messageToSign = $"{method}:{path}:{clientId}:{timestamp}:{nonce}";
        byte[] messageBytes = Encoding.UTF8.GetBytes(messageToSign);

        byte[] signatureBytes = keyManager.SignData(messageBytes);
        string signatureBase64 = Convert.ToBase64String(signatureBytes);

        request.Headers.Add("X-Client-Id", clientId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Signature", signatureBase64);
    }

    public void Dispose()
    {
        _keyManager.Dispose();
        try
        {
            if (File.Exists(_tempKeyPath))
            {
                File.Delete(_tempKeyPath);
            }
        }
        catch
        {
            // Ignore clean up errors
        }
    }
}

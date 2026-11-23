using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

public class ClientStatusEndpointTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _httpClient;
    private readonly string _machineId;
    private readonly string _tempKeyPath;
    private readonly KeyPairManager _keyManager;

    public ClientStatusEndpointTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", "InMemory" }
                });
            });
        });
        _httpClient = _factory.CreateClient();
        _machineId = Guid.NewGuid().ToString();
        _tempKeyPath = Path.Combine(Path.GetTempPath(), $"client_status_int_test_{Guid.NewGuid():N}.dat");

        _keyManager = new KeyPairManager(_tempKeyPath);
        _keyManager.GenerateAndSaveKeys();
    }

    [Fact]
    public async Task ClientStatus_AfterWorkerPolls_ShouldReportOnline()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // Establish the baseline, so the assertions below can only be explained by the poll.
        var before = await GetClientStatusesAsync(appId, appEcdsa);
        Assert.Equal(ClientHealth.Offline, Assert.Single(before).Health);

        // The Worker checking in is what stamps LastSeenUtc - a poll is the heartbeat.
        var pollRequest = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(pollRequest);
        await _httpClient.SendAsync(pollRequest);

        var statuses = await GetClientStatusesAsync(appId, appEcdsa);

        var status = Assert.Single(statuses);
        Assert.Equal(_machineId, status.MachineId);
        Assert.Equal(ClientHealth.Online, status.Health);
        Assert.Equal(0, status.MissedPolls);
        Assert.NotNull(status.LastSeenUtc);
        Assert.NotNull(status.SecondsSinceLastSeen);
        Assert.True(status.SecondsSinceLastSeen < 60, $"Expected a fresh heartbeat, got {status.SecondsSinceLastSeen}s.");
    }

    [Fact]
    public async Task ClientStatus_AfterWorkerReportsVersionAndCapabilities_ShouldReturnThemNormalized()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // Mixed case, stray spaces, a duplicate and an invalid token: the App must only ever see
        // the clean, de-duplicated set.
        await PollAsync(workerVersion: "1.2.0", capabilities: "envelope-v2, PARAMS ,bad token!,params");

        var status = Assert.Single(await GetClientStatusesAsync(appId, appEcdsa));
        Assert.Equal("1.2.0", status.WorkerVersion);
        Assert.Equal(new[] { WorkerCapabilityTokens.EnvelopeV2, WorkerCapabilityTokens.Params }, status.Capabilities);
    }

    [Fact]
    public async Task ClientStatus_WhenPollCarriesNoVersionHeader_ShouldClearPreviouslyReportedCapabilities()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        await PollAsync(workerVersion: "1.2.0", capabilities: "envelope-v2,params");

        // Only a pre-1.2 Worker polls without the header - e.g. one that was downgraded. Keeping
        // the old list would make the App offer features this Worker no longer has.
        await PollAsync(workerVersion: null, capabilities: null);

        var status = Assert.Single(await GetClientStatusesAsync(appId, appEcdsa));
        Assert.Null(status.WorkerVersion);
        Assert.Null(status.Capabilities);
    }

    [Fact]
    public async Task ClientStatus_WhenReportedValuesAreMalformed_ShouldDropThemRatherThanStoreThem()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // 20 valid-looking tokens: only the first 16 are kept.
        string manyTokens = string.Join(',', Enumerable.Range(1, 20).Select(i => $"cap-{i}"));
        await PollAsync(workerVersion: "1.2.0; DROP TABLE \"Clients\"", capabilities: manyTokens);

        var status = Assert.Single(await GetClientStatusesAsync(appId, appEcdsa));
        Assert.Null(status.WorkerVersion);
        Assert.NotNull(status.Capabilities);
        Assert.Equal(16, status.Capabilities.Count);
        Assert.Equal("cap-1", status.Capabilities[0]);
    }

    [Fact]
    public async Task ClientStatus_WhenHeadersArriveOnAnUnverifiedRequest_ShouldNotStoreThem()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // Correct MachineId, but a signature that doesn't verify: the Hub must reject it before
        // touching anything the request claims about the Worker.
        var forged = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(forged);
        forged.Headers.Remove("X-Signature");
        forged.Headers.Add("X-Signature", Convert.ToBase64String(new byte[64]));
        forged.Headers.Add(ProtocolConstants.WorkerVersionHeaderName, "9.9.9");
        forged.Headers.Add(ProtocolConstants.WorkerCapabilitiesHeaderName, "envelope-v2,params,preflight");

        var response = await _httpClient.SendAsync(forged);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var status = Assert.Single(await GetClientStatusesAsync(appId, appEcdsa));
        Assert.Null(status.WorkerVersion);
        Assert.Null(status.Capabilities);
    }

    [Theory]
    // Cadence 12s, grace max(5, 6) = 6s. Missed = floor((age - 6) / 12).
    [InlineData(2, ClientHealth.Online, 0)]     // just checked in
    [InlineData(17, ClientHealth.Online, 0)]    // within the first interval plus grace
    [InlineData(20, ClientHealth.Degraded, 1)]  // one missed confirmation
    [InlineData(35, ClientHealth.Degraded, 2)]  // two missed - still only a warning
    [InlineData(45, ClientHealth.Offline, 3)]   // three missed - now genuinely offline
    [InlineData(600, ClientHealth.Offline, 49)]
    public async Task ClientStatus_ShouldGradeHealthByMissedCheckIns(int ageSeconds, ClientHealth expectedHealth, int expectedMissed)
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        await SetHeartbeatAsync(_machineId, DateTime.UtcNow.AddSeconds(-ageSeconds), pollIntervalSeconds: 12);

        var status = Assert.Single(await GetClientStatusesAsync(appId, appEcdsa));
        Assert.Equal(expectedHealth, status.Health);
        Assert.Equal(expectedMissed, status.MissedPolls);
    }

    [Fact]
    public async Task ClientStatus_ShouldCountMissedCheckInsInTheMachinesOwnCadence()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // The same 60s of silence means very different things at different cadences. At 5s it is
        // ~11 missed check-ins; at 300s the machine is not even due yet. Grading in units of the
        // machine's own interval is what keeps both judgements correct.
        await SetHeartbeatAsync(_machineId, DateTime.UtcNow.AddSeconds(-60), pollIntervalSeconds: 5);
        Assert.Equal(ClientHealth.Offline, Assert.Single(await GetClientStatusesAsync(appId, appEcdsa)).Health);

        await SetHeartbeatAsync(_machineId, DateTime.UtcNow.AddSeconds(-60), pollIntervalSeconds: 300);
        var slow = Assert.Single(await GetClientStatusesAsync(appId, appEcdsa));
        Assert.Equal(ClientHealth.Online, slow.Health);
        Assert.Equal(0, slow.MissedPolls);
    }

    [Fact]
    public async Task ClientStatus_WhenWorkerHasNeverPolled_ShouldReportOfflineWithNoLastSeen()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // Deliberately no poll: registered, but never checked in.
        var statuses = await GetClientStatusesAsync(appId, appEcdsa);

        var status = Assert.Single(statuses);
        Assert.Equal(_machineId, status.MachineId);
        Assert.Equal(ClientHealth.Offline, status.Health);
        Assert.Null(status.LastSeenUtc);
        Assert.Null(status.SecondsSinceLastSeen);

        // Null rather than 0: "never checked in" isn't a countable number of misses.
        Assert.Null(status.MissedPolls);
    }

    [Fact]
    public async Task ClientStatus_SlowPollingWorker_ShouldNotBeMarkedOfflineTooEarly()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // A Worker deliberately configured to poll every 5 minutes, last heard from 200s ago.
        // Against the default cadence that's long dead; against its own reported cadence it
        // hasn't even missed a beat. Without self-tuning this machine would read as permanently
        // offline - the exact bug X-Poll-Interval exists to prevent.
        await SetHeartbeatAsync(_machineId, DateTime.UtcNow.AddSeconds(-200), pollIntervalSeconds: 300);

        var statuses = await GetClientStatusesAsync(appId, appEcdsa);
        Assert.Equal(ClientHealth.Online, Assert.Single(statuses).Health);

        // Same staleness, but now polling on the default cadence: 200s is many missed check-ins.
        await SetHeartbeatAsync(_machineId, DateTime.UtcNow.AddSeconds(-200), pollIntervalSeconds: null);

        statuses = await GetClientStatusesAsync(appId, appEcdsa);
        Assert.Equal(ClientHealth.Offline, Assert.Single(statuses).Health);
    }

    [Fact]
    public async Task ClientStatus_ShouldOnlyReturnMachinesPairedWithTheCallingApp()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // A second machine, registered on the same Hub but paired with a different App. The
        // caller must not be able to see it - that's the endpoint's whole access boundary.
        string otherMachineId = Guid.NewGuid().ToString();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = otherMachineId, PublicKey = "OtherKey", LastSeenUtc = DateTime.UtcNow });
            db.Pairings.Add(new Pairing
            {
                MachineId = otherMachineId,
                AppId = Guid.NewGuid().ToString(),
                AppPublicKey = "OtherAppKey",
                IsLocked = true
            });
            await db.SaveChangesAsync();
        }

        var statuses = await GetClientStatusesAsync(appId, appEcdsa);

        Assert.DoesNotContain(statuses, s => s.MachineId == otherMachineId);
        Assert.Contains(statuses, s => s.MachineId == _machineId);
    }

    [Fact]
    public async Task ClientStatus_WithoutValidSignature_ShouldReturnUnauthorized()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // Correct AppId, but signed with a key the Hub has never seen.
        using var impostorEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/clients/status");
        AddAppSignatureHeaders(request, appId, impostorEcdsa);

        var response = await _httpClient.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>Sends one signed Worker poll, with the self-report headers only when given.</summary>
    private async Task PollAsync(string? workerVersion, string? capabilities)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(request);
        if (workerVersion != null)
        {
            request.Headers.TryAddWithoutValidation(ProtocolConstants.WorkerVersionHeaderName, workerVersion);
        }
        if (capabilities != null)
        {
            request.Headers.TryAddWithoutValidation(ProtocolConstants.WorkerCapabilitiesHeaderName, capabilities);
        }

        var response = await _httpClient.SendAsync(request);
        Assert.True(response.IsSuccessStatusCode, $"Poll failed: {response.StatusCode}");
    }

    private async Task SetHeartbeatAsync(string machineId, DateTime lastSeenUtc, int? pollIntervalSeconds)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        var client = await db.Clients.FirstAsync(c => c.MachineId == machineId);
        client.LastSeenUtc = lastSeenUtc;
        client.PollIntervalSeconds = pollIntervalSeconds;
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Seeds this fixture's machine and a locked pairing to a fresh App identity directly into
    /// the DB, returning the AppId.
    /// </summary>
    private async Task<string> RegisterAndPairAsync(ECDsa appEcdsa)
    {
        string appId = Guid.NewGuid().ToString();

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        db.Clients.Add(new Client
        {
            MachineId = _machineId,
            PublicKey = _keyManager.GetPublicKeyBase64()
        });
        db.Pairings.Add(new Pairing
        {
            MachineId = _machineId,
            AppId = appId,
            AppPublicKey = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo()),
            IsLocked = true,
            AnnouncedToClientAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        return appId;
    }

    private async Task<List<ClientStatus>> GetClientStatusesAsync(string appId, ECDsa appEcdsa)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/clients/status");
        AddAppSignatureHeaders(request, appId, appEcdsa);

        var response = await _httpClient.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var statuses = await response.Content.ReadFromJsonAsync<List<ClientStatus>>(JsonOptions);
        Assert.NotNull(statuses);
        return statuses;
    }

    private void AddAppSignatureHeaders(HttpRequestMessage request, string appId, ECDsa appEcdsa)
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

        string messageToSign = $"{method}:{path}:{appId}:{timestamp}:{nonce}";
        byte[] messageBytes = Encoding.UTF8.GetBytes(messageToSign);
        byte[] signatureBytes = appEcdsa.SignData(messageBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        string signatureBase64 = Convert.ToBase64String(signatureBytes);

        request.Headers.Add("X-App-Id", appId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Signature", signatureBase64);
    }

    private void AddSignatureHeaders(HttpRequestMessage request)
    {
        AddSignatureHeaders(request, _machineId, _keyManager);
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

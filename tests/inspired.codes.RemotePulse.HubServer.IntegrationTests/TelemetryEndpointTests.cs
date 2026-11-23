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

public class TelemetryEndpointTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _httpClient;
    private readonly string _machineId;
    private readonly string _tempKeyPath;
    private readonly KeyPairManager _keyManager;

    public TelemetryEndpointTests(WebApplicationFactory<Program> factory)
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
        _tempKeyPath = Path.Combine(Path.GetTempPath(), $"telemetry_int_test_{Guid.NewGuid():N}.dat");

        _keyManager = new KeyPairManager(_tempKeyPath);
        _keyManager.GenerateAndSaveKeys();
    }

    [Fact]
    public async Task Telemetry_PostLogs_Unsigned_ShouldReturnUnauthorized()
    {
        var entries = new List<TelemetryLogEntry>
        {
            new TelemetryLogEntry { EventName = "Test", Message = "No auth" }
        };
        var postResponse = await _httpClient.PostAsJsonAsync("/api/telemetry/logs", entries);
        Assert.Equal(HttpStatusCode.Unauthorized, postResponse.StatusCode);
    }

    [Fact]
    public async Task Telemetry_PostLogs_UnsupportedProtocolVersion_ShouldReturn426NotWrappedAs401()
    {
        // Regression test: this endpoint's auth branch wraps VerifyClientRequestAsync's error
        // with its own "Client authentication failed: {error}" prefix before handing it to
        // AuthFailureResult. The old string-matching implementation (checking whether the
        // message *started with* "Unsupported protocol version") broke silently here - the
        // prefix meant it never matched, so a genuine protocol-version mismatch reaching this
        // endpoint came back 401 instead of the 426 every other endpoint would have given it.
        // The AuthFailureReason discriminator doesn't care about the text at all, so this must
        // return 426 regardless of what the message got wrapped in.
        using var testKeyManager = new KeyPairManager(Path.Combine(Path.GetTempPath(), $"telemetry_protover_{Guid.NewGuid():N}.dat"));
        testKeyManager.GenerateAndSaveKeys();
        string testMachineId = Guid.NewGuid().ToString();

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = testMachineId, PublicKey = testKeyManager.GetPublicKeyBase64(), DateCreated = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }

        var entries = new List<TelemetryLogEntry> { new TelemetryLogEntry { EventName = "Test", Message = "protocol version probe" } };
        using var postRequest = new HttpRequestMessage(HttpMethod.Post, "/api/telemetry/logs");
        AddSignatureHeaders(postRequest, testMachineId, testKeyManager);
        postRequest.Headers.Add(ProtocolConstants.VersionHeaderName, (ProtocolConstants.CurrentVersionNumber + 1).ToString());
        postRequest.Content = JsonContent.Create(entries);

        var response = await _httpClient.SendAsync(postRequest);

        Assert.Equal(HttpStatusCode.UpgradeRequired, response.StatusCode);
        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Unsupported protocol version", body);
    }

    [Fact]
    public async Task Telemetry_GetLogs_Unsigned_ShouldReturnUnauthorized()
    {
        var queryResponse = await _httpClient.GetAsync("/api/telemetry/logs");
        Assert.Equal(HttpStatusCode.Unauthorized, queryResponse.StatusCode);
    }

    [Fact]
    public async Task Telemetry_PostLogs_EmptyBatch_ShouldReturnBadRequest()
    {
        // Must be signed to pass auth and reach empty check
        using var postRequest = new HttpRequestMessage(HttpMethod.Post, "/api/telemetry/logs");
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            if (!await db.Clients.AnyAsync(c => c.MachineId == _machineId))
            {
                db.Clients.Add(new Client { MachineId = _machineId, PublicKey = _keyManager.GetPublicKeyBase64(), DateCreated = DateTime.UtcNow });
                await db.SaveChangesAsync();
            }
        }
        AddSignatureHeaders(postRequest);
        postRequest.Content = JsonContent.Create(new List<TelemetryLogEntry>());

        var postResponse = await _httpClient.SendAsync(postRequest);
        Assert.Equal(HttpStatusCode.BadRequest, postResponse.StatusCode);
    }

    [Fact]
    public async Task Telemetry_PostLogs_SignedBatch_ShouldIngestAndSanitizeAndQuery()
    {
        // 1. Setup registered client and paired app in DB
        string testMachineId = Guid.NewGuid().ToString();
        using var testKeyManager = new KeyPairManager(Path.Combine(Path.GetTempPath(), $"telemetry_worker_{Guid.NewGuid():N}.dat"));
        testKeyManager.GenerateAndSaveKeys();

        string appId = Guid.NewGuid().ToString();
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPubBase64 = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = testMachineId, PublicKey = testKeyManager.GetPublicKeyBase64(), DateCreated = DateTime.UtcNow });
            db.Pairings.Add(new Pairing { MachineId = testMachineId, AppId = appId, AppPublicKey = appPubBase64, IsLocked = true });
            await db.SaveChangesAsync();
        }

        string uniqueEvent = $"Event_{Guid.NewGuid():N}";
        var entries = new List<TelemetryLogEntry>
        {
            new TelemetryLogEntry
            {
                Source = "Worker",
                MachineId = testMachineId,
                LogLevel = "Error",
                Category = "PollingWorker",
                EventName = uniqueEvent,
                Message = "Command failed at /home/alice/Workspace/file.cs with password=secret123   at System.Threading.Tasks.Task.Wait()",
                DataJson = JsonSerializer.Serialize(new { testId = 123, path = "C:\\ProgramData\\RemotePulse\\key.dat" })
            }
        };

        // Act: POST signed as Worker
        using var postRequest = new HttpRequestMessage(HttpMethod.Post, "/api/telemetry/logs");
        AddSignatureHeaders(postRequest, testMachineId, testKeyManager);
        postRequest.Content = JsonContent.Create(entries);

        var postResponse = await _httpClient.SendAsync(postRequest);
        Assert.Equal(HttpStatusCode.OK, postResponse.StatusCode);

        // Act: GET signed as paired App
        using var queryRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/telemetry/logs?source=Worker&logLevel=Error&limit=10");
        AddAppSignatureHeaders(queryRequest, appId, appEcdsa);

        var queryResponse = await _httpClient.SendAsync(queryRequest);
        Assert.Equal(HttpStatusCode.OK, queryResponse.StatusCode);

        var queried = await queryResponse.Content.ReadFromJsonAsync<List<TelemetryLogEntry>>();
        Assert.NotNull(queried);
        var match = queried.FirstOrDefault(l => l.EventName == uniqueEvent);
        Assert.NotNull(match);
        Assert.Equal("Worker", match.Source);
        Assert.Equal(testMachineId, match.MachineId);
        // Verify sanitization
        Assert.DoesNotContain("/home/alice", match.Message);
        Assert.DoesNotContain("secret123", match.Message);
        Assert.Contains("[PATH]", match.Message);
        Assert.Contains("[REDACTED]", match.Message);
        Assert.Contains("[STACK TRUNCATED]", match.Message);
        Assert.DoesNotContain("C:\\ProgramData", match.DataJson);
    }

    [Fact]
    public async Task Telemetry_PostLogs_NonJsonDataJson_ShouldIngestWithRaw()
    {
        string testMachineId = Guid.NewGuid().ToString();
        using var testKeyManager = new KeyPairManager(Path.Combine(Path.GetTempPath(), $"telemetry_worker_{Guid.NewGuid():N}.dat"));
        testKeyManager.GenerateAndSaveKeys();

        string appId = Guid.NewGuid().ToString();
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPubBase64 = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = testMachineId, PublicKey = testKeyManager.GetPublicKeyBase64(), DateCreated = DateTime.UtcNow });
            db.Pairings.Add(new Pairing { MachineId = testMachineId, AppId = appId, AppPublicKey = appPubBase64, IsLocked = true });
            await db.SaveChangesAsync();
        }

        string uniqueEvent = $"Event_Raw_{Guid.NewGuid():N}";
        string nonJsonPayload = new string('X', 600);
        var entries = new List<TelemetryLogEntry>
        {
            new TelemetryLogEntry
            {
                Source = "Worker",
                MachineId = testMachineId,
                LogLevel = "Error",
                Category = "PollingWorker",
                EventName = uniqueEvent,
                Message = "Test non-JSON telemetry payload",
                DataJson = nonJsonPayload
            }
        };

        using var postRequest = new HttpRequestMessage(HttpMethod.Post, "/api/telemetry/logs");
        AddSignatureHeaders(postRequest, testMachineId, testKeyManager);
        postRequest.Content = JsonContent.Create(entries);

        var postResponse = await _httpClient.SendAsync(postRequest);
        Assert.Equal(HttpStatusCode.OK, postResponse.StatusCode);

        using var queryRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/telemetry/logs?source=Worker&logLevel=Error&limit=10");
        AddAppSignatureHeaders(queryRequest, appId, appEcdsa);

        var queryResponse = await _httpClient.SendAsync(queryRequest);
        Assert.Equal(HttpStatusCode.OK, queryResponse.StatusCode);

        var queried = await queryResponse.Content.ReadFromJsonAsync<List<TelemetryLogEntry>>();
        Assert.NotNull(queried);
        var match = queried.FirstOrDefault(l => l.EventName == uniqueEvent);
        Assert.NotNull(match);
        Assert.Contains("\"raw\":", match.DataJson);
    }

    [Fact]
    public async Task Telemetry_PostLogs_OversizedValidJson_ShouldIngestWithTruncated()
    {
        string testMachineId = Guid.NewGuid().ToString();
        using var testKeyManager = new KeyPairManager(Path.Combine(Path.GetTempPath(), $"telemetry_worker_{Guid.NewGuid():N}.dat"));
        testKeyManager.GenerateAndSaveKeys();

        string appId = Guid.NewGuid().ToString();
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPubBase64 = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = testMachineId, PublicKey = testKeyManager.GetPublicKeyBase64(), DateCreated = DateTime.UtcNow });
            db.Pairings.Add(new Pairing { MachineId = testMachineId, AppId = appId, AppPublicKey = appPubBase64, IsLocked = true });
            await db.SaveChangesAsync();
        }

        string uniqueEvent = $"Event_Trunc_{Guid.NewGuid():N}";
        string largeContent = new string('A', 70 * 1024);
        string validJsonPayload = JsonSerializer.Serialize(new { bigData = largeContent });

        var entries = new List<TelemetryLogEntry>
        {
            new TelemetryLogEntry
            {
                Source = "Worker",
                MachineId = testMachineId,
                LogLevel = "Error",
                Category = "PollingWorker",
                EventName = uniqueEvent,
                Message = "Test oversized JSON telemetry payload",
                DataJson = validJsonPayload
            }
        };

        using var postRequest = new HttpRequestMessage(HttpMethod.Post, "/api/telemetry/logs");
        AddSignatureHeaders(postRequest, testMachineId, testKeyManager);
        postRequest.Content = JsonContent.Create(entries);

        var postResponse = await _httpClient.SendAsync(postRequest);
        Assert.Equal(HttpStatusCode.OK, postResponse.StatusCode);

        using var queryRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/telemetry/logs?source=Worker&logLevel=Error&limit=10");
        AddAppSignatureHeaders(queryRequest, appId, appEcdsa);

        var queryResponse = await _httpClient.SendAsync(queryRequest);
        Assert.Equal(HttpStatusCode.OK, queryResponse.StatusCode);

        var queried = await queryResponse.Content.ReadFromJsonAsync<List<TelemetryLogEntry>>();
        Assert.NotNull(queried);
        var match = queried.FirstOrDefault(l => l.EventName == uniqueEvent);
        Assert.NotNull(match);
        Assert.Contains("\"truncated\":true", match.DataJson);
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

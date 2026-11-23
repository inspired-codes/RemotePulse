using System;
using System.Collections.Generic;
using System.Diagnostics;
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

public class CommandQueueAndPollTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
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

    public CommandQueueAndPollTests(WebApplicationFactory<Program> factory)
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
        _tempKeyPath = Path.Combine(Path.GetTempPath(), $"cmd_queue_poll_int_test_{Guid.NewGuid():N}.dat");

        _keyManager = new KeyPairManager(_tempKeyPath);
        _keyManager.GenerateAndSaveKeys();
    }

    [Fact]
    public async Task Command_Execution_Queue_And_Result_Flow_ShouldSucceed()
    {
        // 1. Seed registered Client + a locked App pairing directly (see RegisterAndPairAsync).
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // 2. Mobile App Queues PowerShell Command with signed App headers
        string commandId = Guid.NewGuid().ToString();
        var queuePayload = new QueueCommandRequest(_machineId, "EncryptedScriptPayloadBase64", ExecutionMode.RunWithHighestLocalPrivileges, commandId);
        var queueHttpRequest = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        queueHttpRequest.Content = JsonContent.Create(queuePayload, options: JsonOptions);
        AddAppSignatureHeaders(queueHttpRequest, appId, appEcdsa);

        var queueResponse = await _httpClient.SendAsync(queueHttpRequest);
        string errorDetails = await queueResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, queueResponse.StatusCode); // Error: {errorDetails}

        // 3. Client Polled Request
        var pollRequest = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(pollRequest);
        var pollResponse = await _httpClient.SendAsync(pollRequest);
        Assert.Equal(HttpStatusCode.OK, pollResponse.StatusCode);

        var polledCommand = await pollResponse.Content.ReadFromJsonAsync<ServerCommand>(JsonOptions);
        Assert.NotNull(polledCommand);
        Assert.Equal(commandId, polledCommand.CommandId);
        Assert.Equal("EncryptedScriptPayloadBase64", polledCommand.Script);
        Assert.Equal(ExecutionMode.RunWithHighestLocalPrivileges, polledCommand.ExecutionMode);

        // 4. Client Posts Command Execution Result
        var resultPayload = new CommandResult
        {
            CommandId = commandId,
            Success = true,
            DurationMs = 124.5,
            IsEncrypted = true,
            EncryptedPayload = "VALID_CIPHERTEXT_BLOB"
        };
        var resultRequest = new HttpRequestMessage(HttpMethod.Post, "/api/commands/results");
        AddSignatureHeaders(resultRequest);
        resultRequest.Content = JsonContent.Create(resultPayload);

        var resultResponse = await _httpClient.SendAsync(resultRequest);
        Assert.Equal(HttpStatusCode.OK, resultResponse.StatusCode);

        // 5. Mobile App Polls for Result
        var getResultRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/commands/results/{commandId}");
        AddAppSignatureHeaders(getResultRequest, appId, appEcdsa);
        var getResultResponse = await _httpClient.SendAsync(getResultRequest);
        Assert.Equal(HttpStatusCode.OK, getResultResponse.StatusCode);

        var fetchedResult = await getResultResponse.Content.ReadFromJsonAsync<CommandResult>();
        Assert.NotNull(fetchedResult);
        Assert.Equal(commandId, fetchedResult.CommandId);
        Assert.True(fetchedResult.Success);
        Assert.True(fetchedResult.IsEncrypted);
        Assert.Equal("VALID_CIPHERTEXT_BLOB", fetchedResult.EncryptedPayload);

        // 6. Unpaired App attempts to read result -> Should be Forbidden (403)
        using var rogueAppEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string rogueAppId = "APP-ROGUE-001";
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Pairings.Add(new Pairing
            {
                MachineId = "OTHER-MACHINE-999",
                AppId = rogueAppId,
                AppPublicKey = Convert.ToBase64String(rogueAppEcdsa.ExportSubjectPublicKeyInfo()),
                IsLocked = true
            });
            await db.SaveChangesAsync();
        }

        var rogueGetResultRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/commands/results/{commandId}");
        AddAppSignatureHeaders(rogueGetResultRequest, rogueAppId, rogueAppEcdsa);
        var rogueGetResultResponse = await _httpClient.SendAsync(rogueGetResultRequest);
        Assert.Equal(HttpStatusCode.Forbidden, rogueGetResultResponse.StatusCode);
    }

    [Fact]
    public async Task Poll_WithWait_ShouldReturnAsSoonAsACommandIsQueued_NotAfterTheFullWindow()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        // Park a poll on an empty queue with a generous window, then queue work behind it. The
        // whole point of long-polling is that this returns on the order of milliseconds rather
        // than sitting out the window, so the assertion is on elapsed time.
        var pollRequest = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll?wait=30");
        AddSignatureHeaders(pollRequest);

        var stopwatch = Stopwatch.StartNew();
        Task<HttpResponseMessage> parked = _httpClient.SendAsync(pollRequest);

        // Give the request time to actually reach the parked state before queueing.
        await Task.Delay(300);

        string commandId = Guid.NewGuid().ToString();
        var queuePayload = new QueueCommandRequest(_machineId, "EncryptedPayload", ExecutionMode.RunAsCurrentUser, commandId);
        var queueRequest = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        queueRequest.Content = JsonContent.Create(queuePayload, options: JsonOptions);
        AddAppSignatureHeaders(queueRequest, appId, appEcdsa);
        Assert.Equal(HttpStatusCode.OK, (await _httpClient.SendAsync(queueRequest)).StatusCode);

        var response = await parked;
        stopwatch.Stop();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var command = await response.Content.ReadFromJsonAsync<ServerCommand>(JsonOptions);
        Assert.NotNull(command);
        Assert.Equal(commandId, command.CommandId);

        // Comfortably under the 30s window, and under the 3s safety-net re-check too - so this
        // can only have been the signal, not a periodic poll of the database.
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3),
            $"Expected the parked poll to be signalled promptly, but it took {stopwatch.Elapsed.TotalSeconds:F1}s.");
    }

    [Fact]
    public async Task Poll_WithWait_ShouldReturnNoContentOnceTheWindowExpires()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await RegisterAndPairAsync(appEcdsa);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll?wait=1");
        AddSignatureHeaders(request);

        var stopwatch = Stopwatch.StartNew();
        var response = await _httpClient.SendAsync(request);
        stopwatch.Stop();

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(stopwatch.Elapsed >= TimeSpan.FromMilliseconds(900),
            $"Expected the poll to hold for its window, but it returned after {stopwatch.Elapsed.TotalMilliseconds:F0}ms.");
    }

    [Fact]
    public async Task Poll_HandingOutACommand_ShouldLeaveAPickupBreadcrumbInSystemLogs()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        var emptyPoll = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(emptyPoll);
        Assert.Equal(HttpStatusCode.NoContent, (await _httpClient.SendAsync(emptyPoll)).StatusCode);

        string commandId = Guid.NewGuid().ToString();
        var queuePayload = new QueueCommandRequest(_machineId, "EncryptedPayload", ExecutionMode.RunAsCurrentUser, commandId, 42);
        var queueRequest = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        queueRequest.Content = JsonContent.Create(queuePayload, options: JsonOptions);
        AddAppSignatureHeaders(queueRequest, appId, appEcdsa);
        Assert.Equal(HttpStatusCode.OK, (await _httpClient.SendAsync(queueRequest)).StatusCode);

        var poll = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(poll);
        Assert.Equal(HttpStatusCode.OK, (await _httpClient.SendAsync(poll)).StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        var pickups = await db.SystemLogs
            .Where(l => l.EventName == "CommandPickedUp" && l.MachineId == _machineId)
            .ToListAsync();

        SystemLogEntity breadcrumb = Assert.Single(pickups);
        Assert.Equal("Hub", breadcrumb.Source);
        Assert.Equal("Commands", breadcrumb.Category);
        Assert.Contains(commandId, breadcrumb.Message);
        using var data = JsonDocument.Parse(breadcrumb.DataJson!);
        Assert.Equal(commandId, data.RootElement.GetProperty("commandId").GetString());
        Assert.Equal("RunAsCurrentUser", data.RootElement.GetProperty("executionMode").GetString());
        Assert.Equal(42, data.RootElement.GetProperty("timeoutSeconds").GetInt32());
    }

    [Fact]
    public async Task Poll_WithWait_ShouldStillReturnImmediatelyWhenWorkIsAlreadyQueued()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);

        string commandId = Guid.NewGuid().ToString();
        var queuePayload = new QueueCommandRequest(_machineId, "EncryptedPayload", ExecutionMode.RunAsCurrentUser, commandId);
        var queueRequest = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        queueRequest.Content = JsonContent.Create(queuePayload, options: JsonOptions);
        AddAppSignatureHeaders(queueRequest, appId, appEcdsa);
        await _httpClient.SendAsync(queueRequest);

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll?wait=30");
        AddSignatureHeaders(request);

        var stopwatch = Stopwatch.StartNew();
        var response = await _httpClient.SendAsync(request);
        stopwatch.Stop();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3),
            "Work queued before the poll arrived must not wait for a signal that already fired.");
    }

    [Fact]
    public async Task Poll_WithoutWait_ShouldKeepTheOriginalImmediateBehaviour()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await RegisterAndPairAsync(appEcdsa);

        // A Worker predating long-polling sends no wait parameter and must not be parked.
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(request);

        var stopwatch = Stopwatch.StartNew();
        var response = await _httpClient.SendAsync(request);
        stopwatch.Stop();

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1),
            $"An unparameterised poll must return at once, but took {stopwatch.Elapsed.TotalMilliseconds:F0}ms.");
    }

    [Fact]
    public async Task Poll_ShouldPersistTheWorkersSelfReportedPollInterval()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await RegisterAndPairAsync(appEcdsa);

        var pollRequest = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(pollRequest);
        pollRequest.Headers.Add("X-Poll-Interval", "300");
        await _httpClient.SendAsync(pollRequest);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        var client = await db.Clients.FirstAsync(c => c.MachineId == _machineId);

        Assert.Equal(300, client.PollIntervalSeconds);
        Assert.NotNull(client.LastSeenUtc);
    }

    [Fact]
    public async Task Poll_MalformedSignatureHeader_ShouldReturnGenericErrorWithoutExceptionDetails()
    {
        // SEC-9 regression: a thrown exception inside signature verification (here, a
        // non-base64 X-Signature) must not leak ex.Message back to the caller.
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Clients.Add(new Client { MachineId = _machineId, PublicKey = _keyManager.GetPublicKeyBase64() });
            await db.SaveChangesAsync();
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        request.Headers.Add("X-Client-Id", _machineId);
        request.Headers.Add("X-Timestamp", DateTimeOffset.UtcNow.ToString("o"));
        request.Headers.Add("X-Nonce", Guid.NewGuid().ToString("N"));
        request.Headers.Add("X-Signature", "not-valid-base64!!!"); // throws in Convert.FromBase64String

        var response = await _httpClient.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        string body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Signature verification failed.", body);
        Assert.DoesNotContain("FormatException", body);
        Assert.DoesNotContain("Base64", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CommandResults_EmptyMachineId_ShouldReturnNotFound()
    {
        string commandId = Guid.NewGuid().ToString();
        string appId = Guid.NewGuid().ToString();
        string testMachineId = Guid.NewGuid().ToString();
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appPubBase64 = Convert.ToBase64String(appEcdsa.ExportSubjectPublicKeyInfo());

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            db.Pairings.Add(new Pairing { MachineId = testMachineId, AppId = appId, AppPublicKey = appPubBase64, IsLocked = true });
            db.CommandResults.Add(new CommandResultEntity
            {
                CommandId = commandId,
                MachineId = "", // Empty MachineId
                Success = true,
                IsEncrypted = true,
                EncryptedPayload = "BLOB",
                DurationMs = 100
            });
            await db.SaveChangesAsync();
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/commands/results/{commandId}");
        AddAppSignatureHeaders(request, appId, appEcdsa);

        var response = await _httpClient.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task CommandQueue_ValidationAndDuplicateCommandIdAsync()
    {
        using var appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string appId = await RegisterAndPairAsync(appEcdsa);
        string commandId = $"CMD-{Guid.NewGuid():N}";

        // 1. First queue succeeds
        var req1 = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        AddAppSignatureHeaders(req1, appId, appEcdsa);
        req1.Content = JsonContent.Create(new QueueCommandRequest(_machineId, "enc-script-1", ExecutionMode.RunAsCurrentUser, commandId, 30));
        var resp1 = await _httpClient.SendAsync(req1);
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);

        // 2. Duplicate commandId returns 409 Conflict
        var req2 = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        AddAppSignatureHeaders(req2, appId, appEcdsa);
        req2.Content = JsonContent.Create(new QueueCommandRequest(_machineId, "enc-script-2", ExecutionMode.RunAsCurrentUser, commandId, 30));
        var resp2 = await _httpClient.SendAsync(req2);
        Assert.Equal(HttpStatusCode.Conflict, resp2.StatusCode);

        // 3. Invalid timeout returns 400 Bad Request
        var req3 = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        AddAppSignatureHeaders(req3, appId, appEcdsa);
        req3.Content = JsonContent.Create(new QueueCommandRequest(_machineId, "enc-script-3", ExecutionMode.RunAsCurrentUser, $"CMD-{Guid.NewGuid():N}", 99999));
        var resp3 = await _httpClient.SendAsync(req3);
        Assert.Equal(HttpStatusCode.BadRequest, resp3.StatusCode);
    }

    [Fact]
    public async Task Command_Result_E2E_Encrypted_ShouldStoreCiphertextAndAssertDatabaseZeroLeakage()
    {
        using var appEcdsa = ECDsa.Create();
        string appId = await RegisterAndPairAsync(appEcdsa);
        string commandId = $"CMD-E2E-RESULT-{Guid.NewGuid():N}";
        string fakeCiphertext = Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });

        var resultPayload = new CommandResult
        {
            CommandId = commandId,
            Success = true,
            DurationMs = 123.45,
            IsEncrypted = true,
            EncryptedPayload = fakeCiphertext
        };

        // 1. Worker posts result
        using var postReq = new HttpRequestMessage(HttpMethod.Post, "/api/commands/results");
        AddSignatureHeaders(postReq);
        postReq.Content = JsonContent.Create(resultPayload);
        using var postResp = await _httpClient.SendAsync(postReq);
        Assert.Equal(HttpStatusCode.OK, postResp.StatusCode);

        // 2. Verify database stored ciphertext and assert zero plaintext output columns in schema
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            var entity = await db.CommandResults.FirstOrDefaultAsync(r => r.CommandId == commandId);
            Assert.NotNull(entity);
            Assert.True(entity.IsEncrypted);
            Assert.Equal(fakeCiphertext, entity.EncryptedPayload);

            // Reflection check: ensure CommandResultEntity has ZERO plaintext output properties
            var entityProperties = typeof(CommandResultEntity).GetProperties().Select(p => p.Name).ToList();
            Assert.DoesNotContain("Output", entityProperties);
            Assert.DoesNotContain("Error", entityProperties);
            Assert.DoesNotContain("CombinedOutput", entityProperties);
            Assert.DoesNotContain("StreamsJson", entityProperties);
        }

        // 3. App retrieves result
        using var getReq = new HttpRequestMessage(HttpMethod.Get, $"/api/commands/results/{commandId}");
        AddAppSignatureHeaders(getReq, appId, appEcdsa);
        using var getResp = await _httpClient.SendAsync(getReq);
        Assert.Equal(HttpStatusCode.OK, getResp.StatusCode);

        var fetchedResult = await getResp.Content.ReadFromJsonAsync<CommandResult>(JsonOptions);
        Assert.NotNull(fetchedResult);
        Assert.Equal(commandId, fetchedResult.CommandId);
        Assert.True(fetchedResult.Success);
        Assert.True(fetchedResult.IsEncrypted);
        Assert.Equal(fakeCiphertext, fetchedResult.EncryptedPayload);
    }

    [Fact]
    public async Task Command_With_UnsupportedProtocolVersion_ShouldReturn426UpgradeRequired()
    {
        using var appEcdsa = ECDsa.Create();
        await RegisterAndPairAsync(appEcdsa);

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(req);
        req.Headers.Add(ProtocolConstants.VersionHeaderName, "99");

        using var resp = await _httpClient.SendAsync(req);
        Assert.Equal(HttpStatusCode.UpgradeRequired, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("Unsupported protocol version 99", body);
    }

    [Fact]
    public async Task Command_With_SupportedProtocolVersion_ShouldSucceed()
    {
        using var appEcdsa = ECDsa.Create();
        await RegisterAndPairAsync(appEcdsa);

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/commands/poll");
        AddSignatureHeaders(req);
        req.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);

        using var resp = await _httpClient.SendAsync(req);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
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

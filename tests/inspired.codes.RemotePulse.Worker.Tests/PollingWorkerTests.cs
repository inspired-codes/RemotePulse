using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using InspiredCodes.Client.PowerShellEngine;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using Xunit;

namespace InspiredCodes.RemotePulse.Worker.Tests;

public class PollingWorkerTests : IDisposable
{
    private readonly string _tempKeyPath;
    private readonly KeyPairManager _keyManager;
    private readonly string _machineId;
    private readonly TestLogger<PollingWorker> _logger;
    private readonly TestPowerShellEngine _psEngine;

    /// <summary>
    /// A per-test temp directory standing in for C:\ProgramData\RemotePulse. These tests used to
    /// read and write the real one - backing up and restoring the developer's actual pairing.json
    /// - which meant they mutated live installation state and failed outright whenever the
    /// installed Worker service held those files. Isolated state is what makes the suite safe to
    /// run unattended.
    /// </summary>
    private readonly string _dataDirectory;
    private readonly string _pairingPath;
    private readonly ECDsa _appEcdsa;
    private readonly string _appPubKeyBase64;

    public PollingWorkerTests()
    {
        _dataDirectory = Path.Combine(Path.GetTempPath(), $"remotepulse_worker_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dataDirectory);

        _tempKeyPath = Path.Combine(_dataDirectory, "client_key.dat");
        _keyManager = new KeyPairManager(_tempKeyPath);
        _keyManager.GenerateAndSaveKeys();
        _machineId = Guid.NewGuid().ToString();
        _logger = new TestLogger<PollingWorker>();
        _psEngine = new TestPowerShellEngine();

        _pairingPath = Path.Combine(_dataDirectory, "pairing.json");

        // Generate App Key Pair for tests and save pairing info
        _appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _appPubKeyBase64 = Convert.ToBase64String(_appEcdsa.ExportSubjectPublicKeyInfo());
        File.WriteAllText(_pairingPath, JsonSerializer.Serialize(new[] { new { AppId = "TEST-APP-999", AppPublicKey = _appPubKeyBase64 } }));
    }

    [Fact]
    public async Task PollAndExecuteAsync_NoContentResponse_ShouldDoNothing()
    {
        // Arrange - capture the headers rather than asserting on them inside the handler.
        // PollAndExecuteAsync wraps its client.SendAsync call in a catch-all that logs and
        // continues (treating any exception as "Hub unreachable") - an assertion thrown inside
        // this delegate would be silently swallowed there instead of failing the test, which is
        // exactly what let this test's signature check go stale and unnoticed through the SEC-9
        // header-signing change. Assert after the poll completes instead, where a failure
        // properly propagates.
        string? capturedClientId = null, capturedTimestamp = null, capturedNonce = null, capturedSignature = null;
        MockHttpMessageHandler handler = new MockHttpMessageHandler(request =>
        {
            capturedClientId = request.Headers.TryGetValues("X-Client-Id", out var idVals) ? idVals.First() : null;
            capturedTimestamp = request.Headers.TryGetValues("X-Timestamp", out var tsVals) ? tsVals.First() : null;
            capturedNonce = request.Headers.TryGetValues("X-Nonce", out var nonceVals) ? nonceVals.First() : null;
            capturedSignature = request.Headers.TryGetValues("X-Signature", out var sigVals) ? sigVals.First() : null;

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        });

        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        var localUiLogger = new TestLogger<LocalUiServer>();
        PollingWorker worker = new PollingWorker(_logger, factory, _keyManager, _psEngine, _machineId, pollIntervalSeconds: 142, localUiLogger, "http://localhost:5000", dataDirectory: _dataDirectory, localUiPort: 0);

        // Act
        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("PollAndExecuteAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);

        Task task = (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;
        await task;

        // Assert: signature headers were present, and the signature verifies against the
        // SEC-9 "METHOD:path:machineId:timestamp:nonce" message.
        Assert.NotNull(capturedClientId);
        Assert.NotNull(capturedTimestamp);
        Assert.NotNull(capturedNonce);
        Assert.NotNull(capturedSignature);
        string message = $"GET:/api/commands/poll:{capturedClientId}:{capturedTimestamp}:{capturedNonce}";
        bool isSignatureValid = _keyManager.VerifyData(Encoding.UTF8.GetBytes(message), Convert.FromBase64String(capturedSignature!));
        Assert.True(isSignatureValid);

        Assert.False(_psEngine.Executed);
    }

    /// <summary>
    /// Builds a hybrid-encrypted, SEC-1/SEC-4 bound-and-signed command envelope, matching what
    /// <c>HubApiClient.SendCommandAsync</c> sends for real. Individual fields can be overridden
    /// or omitted (pass null) to build the malformed/stale/replayed envelopes the SEC-1/SEC-4
    /// regression tests need.
    /// </summary>
    private string BuildEncryptedEnvelope(
        string commandId,
        ExecutionMode executionMode,
        int? timeoutSeconds,
        string script,
        string? issuedAtUtc = null,
        string? nonce = null,
        bool includeExecutionMode = true,
        bool includeIssuedAtUtc = true,
        bool includeNonce = true,
        bool signScriptOnly = false,
        ECDsa? signingKey = null,
        string? replyKeyBase64 = null,
        object? v = null,
        object? innerExecutionModeOverride = null)
    {
        issuedAtUtc ??= DateTime.UtcNow.ToString("o");
        nonce ??= Guid.NewGuid().ToString("N");
        signingKey ??= _appEcdsa;
        replyKeyBase64 ??= Convert.ToBase64String(new byte[32]);

        string payloadToSign = signScriptOnly
            ? script
            : $"{commandId}:{(int)executionMode}:{timeoutSeconds ?? 0}:{issuedAtUtc}:{nonce}:{script}";
        byte[] signatureBytes = signingKey.SignData(Encoding.UTF8.GetBytes(payloadToSign), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        string signatureBase64 = Convert.ToBase64String(signatureBytes);

        var envelope = new Dictionary<string, object?>
        {
            ["CommandId"] = commandId,
            ["TimeoutSeconds"] = timeoutSeconds,
            ["Script"] = script,
            ["Signature"] = signatureBase64,
            ["ReplyKey"] = replyKeyBase64
        };
        if (v != null) envelope["v"] = v;
        if (includeExecutionMode) envelope["ExecutionMode"] = innerExecutionModeOverride ?? executionMode;
        if (includeIssuedAtUtc) envelope["IssuedAtUtc"] = issuedAtUtc;
        if (includeNonce) envelope["Nonce"] = nonce;

        string envelopeJson = JsonSerializer.Serialize(envelope);
        byte[] encryptedBytes = HybridCrypto.Encrypt(Encoding.UTF8.GetBytes(envelopeJson), _keyManager.GetPublicKeyBase64());
        return Convert.ToBase64String(encryptedBytes);
    }

    [Fact]
    public async Task PollAndExecuteAsync_WithCommand_ShouldExecuteAndPostResult()
    {
        // Arrange
        int requestCount = 0;
        CommandResult? postedResult = null;

        // 1. Prepare a fully bound-and-signed, encrypted command envelope (SEC-1/SEC-4).
        string scriptText = "Get-Process";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope("CMD-999", ExecutionMode.RunAsCurrentUser, null, scriptText);

        MockHttpMessageHandler handler = new MockHttpMessageHandler(async request =>
        {
            requestCount++;
            if (request.Method == HttpMethod.Get)
            {
                // GET poll
                ServerCommand payload = new ServerCommand
                {
                    CommandId = "CMD-999",
                    Script = encryptedPayloadBase64,
                    ExecutionMode = ExecutionMode.RunAsCurrentUser
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(payload, options: new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } })
                };
            }
            else if (request.Method == HttpMethod.Post)
            {
                if (request.RequestUri?.AbsolutePath.Contains("telemetry") == true)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK);
                }

                // POST result - capture here, assert after the worker call returns.
                // PollAndExecuteAsync wraps PostResultAsync in a catch-all that logs and
                // swallows any exception, so an assertion thrown inside this handler is
                // silently eaten and never fails the test.
                postedResult = await request.Content!.ReadFromJsonAsync<CommandResult>();
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        var localUiLogger = new TestLogger<LocalUiServer>();
        PollingWorker worker = new PollingWorker(_logger, factory, _keyManager, _psEngine, _machineId, pollIntervalSeconds: 142, localUiLogger, "http://localhost:5000", dataDirectory: _dataDirectory, localUiPort: 0);

        // Configure test engine to return a successful script output
        _psEngine.ResultToReturn = new PowerShellResult
        {
            MachineId = _machineId,
            Success = true,
            Output = "Active processes list",
            CombinedOutput = "Active processes list",
            Duration = TimeSpan.FromMilliseconds(200)
        };

        // Act
        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("PollAndExecuteAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        Task task = (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;
        await task;

        // Assert
        Assert.True(_psEngine.Executed);
        Assert.Equal("Get-Process", _psEngine.LastScript);
        Assert.Equal(3, requestCount); // 1 GET poll, 1 POST telemetry, 1 POST result

        // The result the Worker actually reported back to the Hub (asserted out here so a
        // failure propagates instead of being swallowed by PollAndExecuteAsync's catch).
        Assert.NotNull(postedResult);
        Assert.Equal("CMD-999", postedResult.CommandId);
        Assert.True(postedResult.Success);
        Assert.True(postedResult.IsEncrypted);
        Assert.NotNull(postedResult.EncryptedPayload);

        byte[] rawBlob = Convert.FromBase64String(postedResult.EncryptedPayload);
        byte[] nonceBytes = rawBlob[..12];
        byte[] cipherAndTag = rawBlob[12..];
        byte[] cipherBytes = cipherAndTag[..^16];
        byte[] tagBytes = cipherAndTag[^16..];
        byte[] plainBytes = new byte[cipherBytes.Length];
        using (var aesGcm = new AesGcm(new byte[32], 16))
        {
            aesGcm.Decrypt(nonceBytes, cipherBytes, tagBytes, plainBytes, Encoding.UTF8.GetBytes("CMD-999"));
        }
        var innerPayload = JsonSerializer.Deserialize<CommandResultPayload>(Encoding.UTF8.GetString(plainBytes));
        Assert.NotNull(innerPayload);
        Assert.True(innerPayload.Success);
        Assert.Contains("Active processes", innerPayload.Output);
    }

    [Fact]
    public async Task PollAndExecuteAsync_TamperedExecutionMode_ShouldRejectCommand()
    {
        // Arrange: App signs an envelope with RunAsCurrentUser
        string scriptText = "Get-Process";
        string commandId = "CMD-TAMPER-1";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(commandId, ExecutionMode.RunAsCurrentUser, null, scriptText);

        CommandResult? postedResult = null;
        MockHttpMessageHandler handler = new MockHttpMessageHandler(async request =>
        {
            if (request.Method == HttpMethod.Get)
            {
                // Attacker modifies the outer ExecutionMode to RunWithHighestLocalPrivileges
                ServerCommand payload = new ServerCommand
                {
                    CommandId = commandId,
                    Script = encryptedPayloadBase64,
                    ExecutionMode = ExecutionMode.RunWithHighestLocalPrivileges
                };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(payload, options: new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } })
                };
            }
            else if (request.Method == HttpMethod.Post)
            {
                if (request.RequestUri?.AbsolutePath.Contains("telemetry") == true)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK);
                }
                postedResult = await request.Content!.ReadFromJsonAsync<CommandResult>();
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        var localUiLogger = new TestLogger<LocalUiServer>();
        PollingWorker worker = new PollingWorker(_logger, factory, _keyManager, _psEngine, _machineId, pollIntervalSeconds: 142, localUiLogger, "http://localhost:5000", dataDirectory: _dataDirectory, localUiPort: 0);

        // Act
        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("PollAndExecuteAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        await (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;

        // Assert: script was never executed, and rejection was posted
        Assert.False(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.False(postedResult.Success);
        Assert.False(postedResult.IsEncrypted);
        Assert.Equal("SignatureInvalid", postedResult.RejectionReason);
    }

    [Fact]
    public async Task PollAndExecuteAsync_ReplayedEnvelope_ShouldRejectSecondDelivery()
    {
        // SEC-1: a Hub that re-delivers the exact same (still validly-signed, still-fresh)
        // encrypted envelope a second time must not get it executed again.
        string scriptText = "Get-Process";
        string commandId = "CMD-REPLAY-1";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(commandId, ExecutionMode.RunAsCurrentUser, null, scriptText);

        var postedResults = new List<CommandResult>();
        MockHttpMessageHandler handler = new MockHttpMessageHandler(async request =>
        {
            if (request.Method == HttpMethod.Get)
            {
                ServerCommand payload = new ServerCommand { CommandId = commandId, Script = encryptedPayloadBase64, ExecutionMode = ExecutionMode.RunAsCurrentUser };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(payload, options: new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } })
                };
            }
            if (request.Method == HttpMethod.Post)
            {
                if (request.RequestUri?.AbsolutePath.Contains("telemetry") == true)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK);
                }
                CommandResult? result = await request.Content!.ReadFromJsonAsync<CommandResult>();
                if (result != null) postedResults.Add(result);
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        var localUiLogger = new TestLogger<LocalUiServer>();
        PollingWorker worker = new PollingWorker(_logger, factory, _keyManager, _psEngine, _machineId, pollIntervalSeconds: 142, localUiLogger, "http://localhost:5000", dataDirectory: _dataDirectory, localUiPort: 0);
        _psEngine.ResultToReturn = new PowerShellResult { MachineId = _machineId, Success = true, Output = "ok", CombinedOutput = "ok", Duration = TimeSpan.FromMilliseconds(50) };

        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("PollAndExecuteAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);

        // Act: the Hub delivers the identical envelope on two separate poll cycles.
        await (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;
        await (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;

        // Assert: executed exactly once, second delivery rejected as a replay.
        Assert.Equal(1, _psEngine.ExecutionCount);
        Assert.Equal(2, postedResults.Count);
        Assert.True(postedResults[0].Success);
        Assert.False(postedResults[1].Success);
        Assert.False(postedResults[1].IsEncrypted);
        Assert.Equal("ReplayDetected", postedResults[1].RejectionReason);
    }

    [Fact]
    public async Task PollAndExecuteAsync_StaleIssuedAtUtc_ShouldRejectCommand()
    {
        // SEC-1: an envelope signed more than 5 minutes ago is rejected, bounding how long a
        // captured-but-not-yet-delivered envelope stays usable.
        string scriptText = "Get-Process";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(
            "CMD-STALE-1", ExecutionMode.RunAsCurrentUser, null, scriptText,
            issuedAtUtc: DateTime.UtcNow.AddMinutes(-10).ToString("o"));

        CommandResult? postedResult = await RunSinglePollCycleAsync("CMD-STALE-1", encryptedPayloadBase64, ExecutionMode.RunAsCurrentUser);

        Assert.False(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.False(postedResult.Success);
        Assert.False(postedResult.IsEncrypted);
        Assert.Equal("FreshnessExpired", postedResult.RejectionReason);
    }

    [Fact]
    public async Task PollAndExecuteAsync_MissingExecutionModeInEnvelope_ShouldRejectCommand()
    {
        // SEC-1/SEC-4: ExecutionMode is now mandatory in the signed envelope, not an optional
        // extra the old code only checked "if present."
        string scriptText = "Get-Process";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(
            "CMD-NOMODE-1", ExecutionMode.RunAsCurrentUser, null, scriptText, includeExecutionMode: false);

        CommandResult? postedResult = await RunSinglePollCycleAsync("CMD-NOMODE-1", encryptedPayloadBase64, ExecutionMode.RunAsCurrentUser);

        Assert.False(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.False(postedResult.Success);
        Assert.False(postedResult.IsEncrypted);
        Assert.Equal("EnvelopeUnreadable", postedResult.RejectionReason);
    }

    [Fact]
    public async Task PollAndExecuteAsync_ScriptOnlySignature_ShouldRejectCommand()
    {
        // SEC-4: the old "or verify script-only signature" fallback is gone. A signature made
        // only over the script text (what an attacker limited to that fallback would have) must
        // no longer verify against the bound-envelope message.
        string scriptText = "Get-Process";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(
            "CMD-SCRIPTONLY-1", ExecutionMode.RunAsCurrentUser, null, scriptText, signScriptOnly: true);

        CommandResult? postedResult = await RunSinglePollCycleAsync("CMD-SCRIPTONLY-1", encryptedPayloadBase64, ExecutionMode.RunAsCurrentUser);

        Assert.False(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.False(postedResult.Success);
        Assert.False(postedResult.IsEncrypted);
        Assert.Equal("SignatureInvalid", postedResult.RejectionReason);
    }

    [Fact]
    public async Task PollAndExecuteAsync_UndefinedOuterExecutionMode_ShouldRejectCommand()
    {
        string scriptText = "Get-Process";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(
            "CMD-BADOUTER-1", ExecutionMode.RunAsCurrentUser, null, scriptText);

        CommandResult? postedResult = await RunSinglePollCycleAsync("CMD-BADOUTER-1", encryptedPayloadBase64, (ExecutionMode)99);

        Assert.False(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.False(postedResult.Success);
        Assert.False(postedResult.IsEncrypted);
        Assert.Equal("EnvelopeUnreadable", postedResult.RejectionReason);
    }

    [Theory]
    [InlineData(99)]
    [InlineData("99")]
    [InlineData("UndefinedModeName")]
    public async Task PollAndExecuteAsync_UndefinedInnerExecutionMode_ShouldRejectCommand(object badMode)
    {
        string scriptText = "Get-Process";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(
            "CMD-BADINNER-1", ExecutionMode.RunAsCurrentUser, null, scriptText,
            innerExecutionModeOverride: badMode);

        CommandResult? postedResult = await RunSinglePollCycleAsync("CMD-BADINNER-1", encryptedPayloadBase64, ExecutionMode.RunAsCurrentUser);

        Assert.False(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.False(postedResult.Success);
        Assert.False(postedResult.IsEncrypted);
        Assert.Equal("EnvelopeUnreadable", postedResult.RejectionReason);
    }

    [Theory]
    [InlineData(2, "EnvelopeUnsupported")]
    [InlineData(99, "EnvelopeUnsupported")]
    [InlineData("notANumber", "EnvelopeUnreadable")]
    public async Task PollAndExecuteAsync_EnvelopeVersionGating_ShouldRejectUnsupportedVersions(object version, string expectedReason)
    {
        string scriptText = "Get-Process";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(
            "CMD-VER-1", ExecutionMode.RunAsCurrentUser, null, scriptText, v: version);

        CommandResult? postedResult = await RunSinglePollCycleAsync("CMD-VER-1", encryptedPayloadBase64, ExecutionMode.RunAsCurrentUser);

        Assert.False(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.False(postedResult.Success);
        Assert.False(postedResult.IsEncrypted);
        Assert.Equal(expectedReason, postedResult.RejectionReason);
    }

    [Fact]
    public async Task PollAndExecuteAsync_RequestsIncludeWorkerVersionAndCapabilityHeaders()
    {
        _psEngine.ResultToReturn = new PowerShellResult
        {
            MachineId = _machineId,
            Success = true,
            Output = "P0 Step 2 ok",
            CombinedOutput = "P0 Step 2 ok",
            Duration = TimeSpan.FromMilliseconds(50)
        };

        string scriptText = "Write-Output 'P0 Step 2'";
        string encryptedPayloadBase64 = BuildEncryptedEnvelope(
            "CMD-CAPS-1", ExecutionMode.RunAsCurrentUser, null, scriptText);

        var (postedResult, requests) = await RunSinglePollCycleWithRequestsAsync(
            "CMD-CAPS-1", encryptedPayloadBase64, ExecutionMode.RunAsCurrentUser);

        Assert.True(_psEngine.Executed);
        Assert.NotNull(postedResult);
        Assert.True(postedResult.Success);

        // The header carries the Worker's own <Version> (from the assembly), not a hardcoded string,
        // so a release bump doesn't break this test.
        Assert.Matches(@"^\d+\.\d+\.\d+$", PollingWorker.WorkerVersion);

        // Verify headers on poll (GET)
        var pollRequest = Assert.Single(requests, r => r.Method == HttpMethod.Get);
        Assert.True(pollRequest.Headers.Contains(ProtocolConstants.WorkerVersionHeaderName));
        Assert.Equal(PollingWorker.WorkerVersion, pollRequest.Headers.GetValues(ProtocolConstants.WorkerVersionHeaderName).Single());
        Assert.True(pollRequest.Headers.Contains(ProtocolConstants.WorkerCapabilitiesHeaderName));
        Assert.Equal(string.Empty, pollRequest.Headers.GetValues(ProtocolConstants.WorkerCapabilitiesHeaderName).Single());

        // Verify headers on result post (POST)
        var resultPost = Assert.Single(requests, r => r.Method == HttpMethod.Post && r.RequestUri?.AbsolutePath.Contains("telemetry") != true);
        Assert.True(resultPost.Headers.Contains(ProtocolConstants.WorkerVersionHeaderName));
        Assert.Equal(PollingWorker.WorkerVersion, resultPost.Headers.GetValues(ProtocolConstants.WorkerVersionHeaderName).Single());
        Assert.True(resultPost.Headers.Contains(ProtocolConstants.WorkerCapabilitiesHeaderName));
        Assert.Equal(string.Empty, resultPost.Headers.GetValues(ProtocolConstants.WorkerCapabilitiesHeaderName).Single());
    }

    /// <summary>Runs one poll/execute cycle against a single encrypted envelope and returns the posted result.</summary>
    private async Task<CommandResult?> RunSinglePollCycleAsync(string commandId, string encryptedPayloadBase64, ExecutionMode outerExecutionMode)
    {
        var (result, _) = await RunSinglePollCycleWithRequestsAsync(commandId, encryptedPayloadBase64, outerExecutionMode);
        return result;
    }

    private async Task<(CommandResult? Result, List<HttpRequestMessage> Requests)> RunSinglePollCycleWithRequestsAsync(
        string commandId,
        string encryptedPayloadBase64,
        ExecutionMode outerExecutionMode)
    {
        CommandResult? postedResult = null;
        List<HttpRequestMessage> requests = new();
        MockHttpMessageHandler handler = new MockHttpMessageHandler(async request =>
        {
            requests.Add(request);
            if (request.Method == HttpMethod.Get)
            {
                ServerCommand payload = new ServerCommand { CommandId = commandId, Script = encryptedPayloadBase64, ExecutionMode = outerExecutionMode };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(payload, options: new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } })
                };
            }
            if (request.Method == HttpMethod.Post)
            {
                if (request.RequestUri?.AbsolutePath.Contains("telemetry") == true)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK);
                }
                postedResult = await request.Content!.ReadFromJsonAsync<CommandResult>();
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        var localUiLogger = new TestLogger<LocalUiServer>();
        PollingWorker worker = new PollingWorker(_logger, factory, _keyManager, _psEngine, _machineId, pollIntervalSeconds: 142, localUiLogger, "http://localhost:5000", dataDirectory: _dataDirectory, localUiPort: 0);

        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("PollAndExecuteAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        await (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;

        return (postedResult, requests);
    }

    [Fact]
    public async Task PollAndExecuteAsync_Unauthorized_ShouldNotAttemptAutoRegistration()
    {
        // Arrange
        int requestCount = 0;
        MockHttpMessageHandler handler = new MockHttpMessageHandler(request =>
        {
            requestCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
        });

        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        var localUiLogger = new TestLogger<LocalUiServer>();
        PollingWorker worker = new PollingWorker(_logger, factory, _keyManager, _psEngine, _machineId, pollIntervalSeconds: 142, localUiLogger, "http://localhost:5000", dataDirectory: _dataDirectory, localUiPort: 0);

        // Act
        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("PollAndExecuteAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        Task task = (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;
        await task;

        // Assert: only the original poll request was made. A 401 just gets logged, pointing
        // the operator at the local onboarding page to complete co-presence pairing.
        Assert.Equal(1, requestCount);
    }

    [Fact]
    public void LoadPairings_CorruptPairingJson_ShouldLogErrorAndTreatAsUnpaired()
    {
        // Write corrupt JSON to pairing file
        File.WriteAllText(_pairingPath, "{ this is not valid json");

        using var handler = new MockHttpMessageHandler(req => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent)));
        var factory = new TestHttpClientFactory(handler);

        using var worker = new PollingWorker(
            _logger,
            factory,
            _keyManager,
            _psEngine,
            _machineId,
            pollIntervalSeconds: 1,
            new TestLogger<LocalUiServer>(),
            "http://localhost:8080",
            dataDirectory: _dataDirectory,
            localUiPort: 0);

        var method = typeof(PollingWorker).GetMethod("LoadPairings", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        var result = method.Invoke(worker, null) as System.Collections.IList;

        Assert.NotNull(result);
        Assert.Empty(result);
        Assert.Contains(_logger.Messages, m => m.Contains("pairing.json at") && m.Contains("could not be parsed; treating as unpaired."));
    }

    private async Task<bool> RunPairingAnnounceCycleAsync(string announcementScript, LocalUiServer localUiServer)
    {
        var commandPayload = new
        {
            CommandId = "PAIRING-ANNOUNCE",
            Script = announcementScript,
            ExecutionMode = ExecutionMode.RunAsCurrentUser,
            IsHandshake = true
        };

        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(commandPayload)
            }));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        using PollingWorker worker = new PollingWorker(
            _logger,
            factory,
            _keyManager,
            _psEngine,
            _machineId,
            pollIntervalSeconds: 142,
            new TestLogger<LocalUiServer>(),
            "http://localhost:5000",
            dataDirectory: _dataDirectory,
            localUiPort: 0,
            localUiServer: localUiServer);

        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("PollAndExecuteAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        var task = method.Invoke(worker, new object[] { CancellationToken.None }) as Task<bool>;
        Assert.NotNull(task);
        return await task;
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_Valid5PartAnnouncement_ShouldAcceptAndSavePairing()
    {
        if (File.Exists(_pairingPath))
        {
            File.Delete(_pairingPath);
        }

        string legitAppId = "LEGIT-APP-" + Guid.NewGuid().ToString("N")[..6];
        string legitSecret = PairingCrypto.GenerateSecret();

        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        using var localUiServer = new LocalUiServer(new TestLogger<LocalUiServer>(), _keyManager, factory, _machineId, "http://localhost:5000", port: 0);
        string pid = localUiServer.RegisterSecretForTesting(legitSecret);
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64());
        string validTag = PairingCrypto.ComputeAppBindTag(legitSecret, pid, workerFp, legitAppId, _appPubKeyBase64);

        bool handled = await RunPairingAnnounceCycleAsync($"PAIRING:{legitAppId}:{_appPubKeyBase64}:{pid}:{validTag}", localUiServer);

        Assert.True(handled);
        Assert.Contains(_logger.Messages, m => m.Contains("Pairing confirmed via co-presence") && m.Contains(legitAppId));

        string pairingJson = File.Exists(_pairingPath) ? File.ReadAllText(_pairingPath) : string.Empty;
        Assert.Contains(legitAppId, pairingJson);
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_WrongAppBindTag_ShouldRejectAndNotSavePairing()
    {
        if (File.Exists(_pairingPath)) File.Delete(_pairingPath);

        string attackerAppId = "ATTACKER-APP-" + Guid.NewGuid().ToString("N")[..6];
        string legitSecret = PairingCrypto.GenerateSecret();

        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        using var localUiServer = new LocalUiServer(new TestLogger<LocalUiServer>(), _keyManager, factory, _machineId, "http://localhost:5000", port: 0);
        string pid = localUiServer.RegisterSecretForTesting(legitSecret);
        string wrongTag = PairingCrypto.GenerateSecret(); // 43 base64url chars, but not the valid HMAC tag

        bool handled = await RunPairingAnnounceCycleAsync($"PAIRING:{attackerAppId}:{_appPubKeyBase64}:{pid}:{wrongTag}", localUiServer);

        Assert.True(handled);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: invalid AppBindTag") && m.Contains(attackerAppId));
        Assert.False(File.Exists(_pairingPath));
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_UnknownOrExpiredPairingId_ShouldRejectAndNotSavePairing()
    {
        if (File.Exists(_pairingPath)) File.Delete(_pairingPath);

        string attackerAppId = "ATTACKER-APP-" + Guid.NewGuid().ToString("N")[..6];
        string legitSecret = PairingCrypto.GenerateSecret();
        string expiredSecret = PairingCrypto.GenerateSecret();

        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        using var localUiServer = new LocalUiServer(new TestLogger<LocalUiServer>(), _keyManager, factory, _machineId, "http://localhost:5000", port: 0);
        localUiServer.RegisterSecretForTesting(legitSecret);
        string expiredPid = localUiServer.RegisterSecretForTesting(expiredSecret, validity: TimeSpan.FromMilliseconds(-50));
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64());

        // 1. Unknown pid
        string unknownPid = PairingCrypto.DerivePairingId(PairingCrypto.GenerateSecret());
        string fakeTag = PairingCrypto.GenerateSecret();
        bool handledUnknown = await RunPairingAnnounceCycleAsync($"PAIRING:{attackerAppId}:{_appPubKeyBase64}:{unknownPid}:{fakeTag}", localUiServer);
        Assert.True(handledUnknown);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: unknown or expired pairing ID"));
        Assert.False(File.Exists(_pairingPath));

        // 2. Expired pid
        _logger.Messages.Clear();
        string expiredTag = PairingCrypto.ComputeAppBindTag(expiredSecret, expiredPid, workerFp, attackerAppId, _appPubKeyBase64);
        bool handledExpired = await RunPairingAnnounceCycleAsync($"PAIRING:{attackerAppId}:{_appPubKeyBase64}:{expiredPid}:{expiredTag}", localUiServer);
        Assert.True(handledExpired);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: unknown or expired pairing ID"));
        Assert.False(File.Exists(_pairingPath));
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_TagComputedForAnotherWorkerFingerprint_ShouldReject()
    {
        if (File.Exists(_pairingPath)) File.Delete(_pairingPath);

        string appId = "APP-" + Guid.NewGuid().ToString("N")[..6];
        string legitSecret = PairingCrypto.GenerateSecret();

        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        using var localUiServer = new LocalUiServer(new TestLogger<LocalUiServer>(), _keyManager, factory, _machineId, "http://localhost:5000", port: 0);
        string pid = localUiServer.RegisterSecretForTesting(legitSecret);

        // Compute tag bound to a DIFFERENT Worker public key fingerprint
        string otherWorkerFp = PairingCrypto.ComputePublicKeyFingerprint(_appPubKeyBase64);
        string tagForOtherWorker = PairingCrypto.ComputeAppBindTag(legitSecret, pid, otherWorkerFp, appId, _appPubKeyBase64);

        bool handled = await RunPairingAnnounceCycleAsync($"PAIRING:{appId}:{_appPubKeyBase64}:{pid}:{tagForOtherWorker}", localUiServer);

        Assert.True(handled);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: invalid AppBindTag") && m.Contains(appId));
        Assert.False(File.Exists(_pairingPath));
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_3PartV1Form_ShouldRejectevenWithKnownSecret()
    {
        if (File.Exists(_pairingPath)) File.Delete(_pairingPath);

        string appId = "APP-V1-" + Guid.NewGuid().ToString("N")[..6];
        string legitSecret = PairingCrypto.GenerateSecret();

        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        using var localUiServer = new LocalUiServer(new TestLogger<LocalUiServer>(), _keyManager, factory, _machineId, "http://localhost:5000", port: 0);
        string pid = localUiServer.RegisterSecretForTesting(legitSecret);

        // 3-part announcement with raw S or pid must be rejected (v1 handling removed)
        bool handledRawS = await RunPairingAnnounceCycleAsync($"PAIRING:{appId}:{_appPubKeyBase64}:{legitSecret}", localUiServer);
        Assert.True(handledRawS);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: expected 5-part v2 announcement"));
        Assert.False(File.Exists(_pairingPath));

        _logger.Messages.Clear();
        bool handledPidOnly = await RunPairingAnnounceCycleAsync($"PAIRING:{appId}:{_appPubKeyBase64}:{pid}", localUiServer);
        Assert.True(handledPidOnly);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: expected 5-part v2 announcement"));
        Assert.False(File.Exists(_pairingPath));
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_WhenAlreadyPairedWithDifferentApp_ShouldRejectAndNotSavePairing()
    {
        // Ensure worker is already paired with TEST-APP-999 (from constructor)
        string existingAppId = "TEST-APP-999";
        string differentAppId = "OTHER-APP-" + Guid.NewGuid().ToString("N")[..6];
        string validSecret = PairingCrypto.GenerateSecret();

        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        using var localUiServer = new LocalUiServer(new TestLogger<LocalUiServer>(), _keyManager, factory, _machineId, "http://localhost:5000", port: 0);
        string pid = localUiServer.RegisterSecretForTesting(validSecret);
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64());
        string validTag = PairingCrypto.ComputeAppBindTag(validSecret, pid, workerFp, differentAppId, _appPubKeyBase64);

        bool handled = await RunPairingAnnounceCycleAsync($"PAIRING:{differentAppId}:{_appPubKeyBase64}:{pid}:{validTag}", localUiServer);

        Assert.True(handled);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: Worker already paired with a different Mobile device"));

        // Ensure different app was NOT saved and existing pairing remains intact
        string pairingJson = File.ReadAllText(_pairingPath);
        Assert.Contains(existingAppId, pairingJson);
        Assert.DoesNotContain(differentAppId, pairingJson);
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_WhenRePairingSameApp_ShouldAcceptAndRotateKey()
    {
        // Re-pairing the SAME AppId (e.g. key rotation) is allowed
        string sameAppId = "TEST-APP-999";
        using var newAppEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string newAppPublicKey = Convert.ToBase64String(newAppEcdsa.ExportSubjectPublicKeyInfo());
        string validSecret = PairingCrypto.GenerateSecret();

        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));
        using var localUiServer = new LocalUiServer(new TestLogger<LocalUiServer>(), _keyManager, factory, _machineId, "http://localhost:5000", port: 0);
        string pid = localUiServer.RegisterSecretForTesting(validSecret);
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64());
        string validTag = PairingCrypto.ComputeAppBindTag(validSecret, pid, workerFp, sameAppId, newAppPublicKey);

        bool handled = await RunPairingAnnounceCycleAsync($"PAIRING:{sameAppId}:{newAppPublicKey}:{pid}:{validTag}", localUiServer);

        Assert.True(handled);
        Assert.Contains(_logger.Messages, m => m.Contains("Pairing confirmed via co-presence") && m.Contains(sameAppId));

        // Ensure pairing was updated with the new key
        using var doc = JsonDocument.Parse(File.ReadAllText(_pairingPath));
        var element = doc.RootElement.EnumerateArray().First(p => p.GetProperty("AppId").GetString() == sameAppId);
        Assert.Equal(newAppPublicKey, element.GetProperty("AppPublicKey").GetString());
    }

    [Fact]
    public async Task PollAndExecuteAsync_PairingAnnounce_WhenLocalUiServerIsNull_ShouldRejectFailClosedAndLeavePairingUnchanged()
    {
        // Even with a syntactically valid 5-part announcement for the already-paired AppId, if
        // _localUiServer is null (no secret ring to verify against), the Worker must fail closed
        // and leave pairing.json untouched.
        string sameAppId = "TEST-APP-999";
        using var attackerEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string attackerPublicKey = Convert.ToBase64String(attackerEcdsa.ExportSubjectPublicKeyInfo());
        string secret = PairingCrypto.GenerateSecret();
        string pid = PairingCrypto.DerivePairingId(secret);
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64());
        string validTag = PairingCrypto.ComputeAppBindTag(secret, pid, workerFp, sameAppId, attackerPublicKey);

        bool handled = await RunPairingAnnounceCycleAsync($"PAIRING:{sameAppId}:{attackerPublicKey}:{pid}:{validTag}", localUiServer: null);

        Assert.True(handled);
        Assert.Contains(_logger.Messages, m => m.Contains("PAIRING announcement rejected: Local UI server is not active"));

        using var doc = JsonDocument.Parse(File.ReadAllText(_pairingPath));
        var element = doc.RootElement.EnumerateArray().First(p => p.GetProperty("AppId").GetString() == sameAppId);
        Assert.Equal(_appPubKeyBase64, element.GetProperty("AppPublicKey").GetString());
    }

    [Fact]
    public async Task ReleasePairingOnHub_ShouldUseTheRegisteredHubHttpClient()
    {
        // Regression test: ReleasePairingOnHubAsync (SEC-2's unpair -> Hub release call) once
        // requested the HttpClient by the wrong name ("HubServer" instead of "RemotePulseHub",
        // the only name Program.cs actually registers via AddHttpClient with the Hub's
        // BaseAddress). CreateClient() doesn't throw on an unregistered name - it just returns a
        // default client with no BaseAddress - so the call failed with
        // InvalidOperationException every single time in production, silently swallowed by the
        // catch block, and 155/155 tests still passed because TestHttpClientFactory (above)
        // ignores the requested name entirely. Asserting on the recorded name is what makes this
        // class of bug visible to the suite.
        TestHttpClientFactory factory = new TestHttpClientFactory(new MockHttpMessageHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));

        using PollingWorker worker = new PollingWorker(
            _logger,
            factory,
            _keyManager,
            _psEngine,
            _machineId,
            pollIntervalSeconds: 142,
            new TestLogger<LocalUiServer>(),
            "http://localhost:5000",
            dataDirectory: _dataDirectory,
            localUiPort: 0);

        System.Reflection.MethodInfo? method = typeof(PollingWorker).GetMethod("ReleasePairingOnHubAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(method);
        var task = method.Invoke(worker, new object[] { "TEST-APP-999" }) as Task;
        Assert.NotNull(task);
        await task;

        Assert.Contains("RemotePulseHub", factory.RequestedClientNames);
    }

    [Fact]
    public void EnforceSizeCap_WhenHugeError_TruncatesErrorUnderCap()
    {
        string hugeError = new string('B', 8 * 1024 * 1024);
        var payload = new CommandResultPayload
        {
            Success = false,
            DurationMs = 1234,
            Output = string.Empty,
            Error = hugeError,
            CombinedOutput = hugeError,
            Streams = null
        };

        var method = typeof(PollingWorker).GetMethod("EnforceSizeCap", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);

        var result = (CommandResultPayload)method.Invoke(null, new object[] { payload })!;
        Assert.NotNull(result);

        string serialized = JsonSerializer.Serialize(result);
        int byteCount = Encoding.UTF8.GetByteCount(serialized);

        // Must be capped within 7MB
        Assert.True(byteCount <= 7 * 1024 * 1024, $"Payload size was {byteCount} bytes, exceeding 7MB cap.");
        Assert.Contains("[Output truncated by Worker at 7MB payload cap]", result.Error);
    }

    [Fact]
    public void EnforceSizeCap_WhenHugeStreams_DropsStreamsUnderCap()
    {
        string hugeDetails = new string('E', 8 * 1024 * 1024);
        var streams = new CommandStreams(
            Warnings: null,
            Errors: null,
            Information: null,
            Verbose: null,
            Debug: null,
            ExceptionDetails: hugeDetails
        );

        var payload = new CommandResultPayload
        {
            Success = false,
            DurationMs = 1234,
            Output = "Short output",
            Error = string.Empty,
            CombinedOutput = "Short output",
            Streams = streams
        };

        var method = typeof(PollingWorker).GetMethod("EnforceSizeCap", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);

        var result = (CommandResultPayload)method.Invoke(null, new object[] { payload })!;
        Assert.NotNull(result);

        string serialized = JsonSerializer.Serialize(result);
        int byteCount = Encoding.UTF8.GetByteCount(serialized);

        // Must be capped within 7MB
        Assert.True(byteCount <= 7 * 1024 * 1024, $"Payload size was {byteCount} bytes, exceeding 7MB cap.");
        Assert.Null(result.Streams);
        Assert.Contains("[Streams omitted by Worker at 7MB payload cap]", result.CombinedOutput);
    }

    public void Dispose()
    {
        _keyManager.Dispose();
        _appEcdsa.Dispose();

        // Everything this fixture touched lives under one temp directory, so cleanup is a single
        // recursive delete - no restoring anyone's real installation state.
        try
        {
            if (Directory.Exists(_dataDirectory))
            {
                Directory.Delete(_dataDirectory, recursive: true);
            }
        }
        catch { }
    }
}

// Stubs for testing
public class TestPowerShellEngine : IPowerShellEngine
{
    public bool Executed { get; private set; }
    public int ExecutionCount { get; private set; }
    public string LastScript { get; private set; } = string.Empty;
    public ExecutionMode LastExecutionMode { get; private set; }
    public PowerShellResult ResultToReturn { get; set; } = new();

    public Task<PowerShellResult> ExecuteScriptAsync(string script, ExecutionMode executionMode, TimeSpan? timeout = null)
    {
        Executed = true;
        ExecutionCount++;
        LastScript = script;
        LastExecutionMode = executionMode;
        return Task.FromResult(ResultToReturn);
    }
}

public class TestHttpClientFactory : IHttpClientFactory
{
    private readonly HttpMessageHandler _handler;

    /// <summary>
    /// Every name CreateClient was asked for, in order. Production code must request the exact
    /// name Program.cs registers ("RemotePulseHub") to get a client with the Hub's BaseAddress
    /// configured - a wrong string still "works" here (this factory ignores the name and always
    /// returns a functioning client), so without recording and asserting on this, a typo'd name
    /// is invisible to the test suite while silently breaking the real DI-registered client.
    /// </summary>
    public List<string> RequestedClientNames { get; } = new();

    public TestHttpClientFactory(HttpMessageHandler handler)
    {
        _handler = handler;
    }

    public HttpClient CreateClient(string name)
    {
        RequestedClientNames.Add(name);
        HttpClient client = new HttpClient(_handler);
        client.BaseAddress = new Uri("http://localhost/");
        return client;
    }
}

public class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _sendAsyncFunc;

    public MockHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> sendAsyncFunc)
    {
        _sendAsyncFunc = sendAsyncFunc;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return _sendAsyncFunc(request);
    }
}

public class TestLogger<T> : ILogger<T>
{
    public System.Collections.Generic.List<string> Messages { get; } = new();
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        Messages.Add(formatter(state, exception));
    }
}

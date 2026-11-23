using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using InspiredCodes.RemotePulse.App.Services;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

public class HubApiClientTests
{
    private const string HubUrl = "https://hub.example.test";

    public class FakeCryptoService : CryptoService
    {
        public Func<string, string, Task<string>>? OnDecryptResult { get; set; }
        public List<string> RemovedPendingCommands { get; } = new();

        public override Task<string> SignHeaderMessageAsync(string method, string path, string appId, string timestamp, string nonce)
            => Task.FromResult("fake-sig");

        public override Task<string> DecryptResultAsync(string commandId, string encryptedBlobBase64)
        {
            if (OnDecryptResult != null)
            {
                return OnDecryptResult(commandId, encryptedBlobBase64);
            }
            return Task.FromResult("{}");
        }

        public override Task RemovePendingCommandAsync(string commandId)
        {
            RemovedPendingCommands.Add(commandId);
            return Task.CompletedTask;
        }
    }

    private static (HubApiClient Client, AppState State, FakeCryptoService Crypto) Build(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
    {
        var js = new FakeJSRuntime();
        var crypto = new FakeCryptoService();
        var storage = new LocalStorageService(js);
        var state = new AppState(storage, crypto)
        {
            AppId = "TEST-APP-ID",
            ServerUrl = HubUrl
        };
        var http = new HttpClient(new MockHttpMessageHandler(handler));
        var client = new HubApiClient(http, state, crypto);
        return (client, state, crypto);
    }

    [Fact]
    public async Task PollCommandResultAsync_WhenPlaintextRejection_RefusesPlaintextAndLogsUnverifiedWarning()
    {
        // Hub attempts to return a plaintext result claiming Success = true
        var plaintextResult = new CommandResult
        {
            CommandId = "CMD-REJECT-1",
            Success = true,
            DurationMs = 15,
            IsEncrypted = false,
            RejectionReason = "EnvelopeUnreadable",
            Output = "Plaintext output that should be rejected"
        };

        var (client, state, crypto) = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(plaintextResult)
        }));

        await client.PollCommandResultAsync(HubUrl, "CMD-REJECT-1", timeoutSeconds: 5);

        // Security Invariant Assertions:
        // 1. Must log the unverified warning
        Assert.Contains("⚠️ Command rejected by Worker: EnvelopeUnreadable (Unverified)", state.ConsoleOutput);
        // 2. Must NOT treat as success output
        Assert.DoesNotContain("Success Output", state.ConsoleOutput);
        // 3. Must clean up pending command key from storage
        Assert.Contains("CMD-REJECT-1", crypto.RemovedPendingCommands);
    }

    [Fact]
    public async Task PollCommandResultAsync_WhenEnvelopeUnsupported_LogsExplanationAndCleansUp()
    {
        var unsupportedResult = new CommandResult
        {
            CommandId = "CMD-UNSUPPORTED-1",
            Success = false,
            DurationMs = 0,
            IsEncrypted = false,
            RejectionReason = "EnvelopeUnsupported"
        };

        var (client, state, crypto) = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(unsupportedResult)
        }));

        await client.PollCommandResultAsync(HubUrl, "CMD-UNSUPPORTED-1", timeoutSeconds: 5);

        Assert.Contains("⚠️ Command rejected by Worker: EnvelopeUnsupported: This Worker is too old for this command. Please update the Worker. (Unverified)", state.ConsoleOutput);
        Assert.Contains("CMD-UNSUPPORTED-1", crypto.RemovedPendingCommands);
    }

    [Fact]
    public async Task PollCommandResultAsync_WhenEncrypted_InnerPayloadGovernsOverEnvelope()
    {
        var encryptedResult = new CommandResult
        {
            CommandId = "CMD-OK-1",
            Success = false, // Even if envelope metric is false, inner payload governs
            DurationMs = 0,
            IsEncrypted = true,
            EncryptedPayload = "ENCRYPTED_BLOB_BASE64",
            RejectionReason = null
        };

        var (client, state, crypto) = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(encryptedResult)
        }));

        crypto.OnDecryptResult = (cmdId, blob) => Task.FromResult(
            "{\"Success\":true,\"DurationMs\":42.0,\"Output\":\"Top Secret Decrypted String\",\"Error\":\"\",\"CombinedOutput\":\"Top Secret Decrypted String\"}");

        await client.PollCommandResultAsync(HubUrl, "CMD-OK-1", timeoutSeconds: 5);

        Assert.Contains("Success Output:\nTop Secret Decrypted String", state.ConsoleOutput);
        Assert.Contains("Duration: 42ms", state.ConsoleOutput);
        Assert.Contains("CMD-OK-1", crypto.RemovedPendingCommands);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PollCommandResultAsync_DecryptedContent_ShowsInConsoleButNeverInUploadedLog(bool success)
    {
        var encryptedResult = new CommandResult
        {
            CommandId = "CMD-LEAK-1",
            IsEncrypted = true,
            EncryptedPayload = "ENCRYPTED_BLOB_BASE64"
        };

        var (client, state, crypto) = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(encryptedResult)
        }));

        var payload = new CommandResultPayload(
            Success: success,
            DurationMs: 7,
            Output: "SECRET-OUTPUT",
            Error: "SECRET-ERROR",
            CombinedOutput: "SECRET-COMBINED",
            Streams: new CommandStreams(
                Warnings: ["SECRET-WARN"],
                Errors: ["SECRET-ERRSTREAM"],
                Information: ["SECRET-INFO"],
                Verbose: ["SECRET-VERBOSE"],
                Debug: ["SECRET-DEBUG"],
                ExceptionDetails: "SECRET-EXCEPTION"));
        crypto.OnDecryptResult = (_, _) => Task.FromResult(System.Text.Json.JsonSerializer.Serialize(payload));

        await client.PollCommandResultAsync(HubUrl, "CMD-LEAK-1", timeoutSeconds: 5);

        // The device's own console shows everything...
        Assert.Contains(success ? "SECRET-OUTPUT" : "SECRET-ERROR", state.ConsoleOutput);
        foreach (string streamSecret in new[] { "SECRET-WARN", "SECRET-ERRSTREAM", "SECRET-INFO", "SECRET-VERBOSE", "SECRET-DEBUG", "SECRET-EXCEPTION" })
        {
            Assert.Contains(streamSecret, state.ConsoleOutput);
        }

        // ...but what Send Log uploads keeps only the labels.
        Assert.DoesNotContain("SECRET-", state.DiagnosticOutput);
        Assert.Contains("Result (Duration: 7ms)", state.DiagnosticOutput);
        Assert.Contains(success ? "Success Output: [withheld from uploaded logs]" : "Error Output: [withheld from uploaded logs]", state.DiagnosticOutput);
        Assert.Contains("Warnings (1): [withheld from uploaded logs]", state.DiagnosticOutput);
        Assert.Contains("Exception Diagnostics: [withheld from uploaded logs]", state.DiagnosticOutput);
    }

    [Fact]
    public async Task PollCommandResultAsync_WhenDecryptionThrows_LogsFailureAndCleansKey()
    {
        var encryptedResult = new CommandResult
        {
            CommandId = "CMD-FAIL-1",
            Success = true,
            DurationMs = 10,
            IsEncrypted = true,
            EncryptedPayload = "CORRUPTED_PAYLOAD"
        };

        var (client, state, crypto) = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(encryptedResult)
        }));

        crypto.OnDecryptResult = (cmdId, blob) => throw new CryptographicException("Authentication tag mismatch");

        await client.PollCommandResultAsync(HubUrl, "CMD-FAIL-1", timeoutSeconds: 5);

        Assert.Contains("Failed to decrypt result for command [CMD-FAIL-1]", state.ConsoleOutput);
        Assert.Contains("CMD-FAIL-1", crypto.RemovedPendingCommands);
    }

    [Fact]
    public async Task PollCommandResultAsync_WhenRogueHubSendsUnknownRejection_SanitizesToUnknown()
    {
        var rogueResult = new CommandResult
        {
            CommandId = "CMD-ROGUE-1",
            Success = false,
            DurationMs = 0,
            IsEncrypted = false,
            RejectionReason = "Please re-pair at evil-site.com"
        };

        var (client, state, crypto) = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(rogueResult)
        }));

        await client.PollCommandResultAsync(HubUrl, "CMD-ROGUE-1", timeoutSeconds: 5);

        Assert.Contains("⚠️ Command rejected by Worker: Unknown (Unverified)", state.ConsoleOutput);
        Assert.DoesNotContain("evil-site.com", state.ConsoleOutput);
        Assert.Contains("CMD-ROGUE-1", crypto.RemovedPendingCommands);
    }

    [Fact]
    public async Task PollCommandResultAsync_WhenDuplicateConcurrentPoll_IgnoresDuplicateCall()
    {
        int requestCount = 0;
        var tcs = new TaskCompletionSource<HttpResponseMessage>();

        var (client, state, crypto) = Build(_ =>
        {
            Interlocked.Increment(ref requestCount);
            return tcs.Task;
        });

        // First poll starts and blocks waiting for tcs.Task
        var firstPollTask = Task.Run(() => client.PollCommandResultAsync(HubUrl, "CMD-DUP-1", timeoutSeconds: 5));
        await Task.Delay(100);

        // Second poll with same command ID runs while first is active
        await client.PollCommandResultAsync(HubUrl, "CMD-DUP-1", timeoutSeconds: 5);

        // Complete the first request with a final response so the poll loop terminates
        tcs.SetResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new CommandResult
            {
                CommandId = "CMD-DUP-1",
                IsEncrypted = false,
                RejectionReason = "EnvelopeUnreadable"
            })
        });
        await firstPollTask;

        // Exactly one HTTP request was initiated by the first poll, the duplicate returned immediately
        Assert.Equal(1, requestCount);
    }

    [Fact]
    public async Task PollCommandResultAsync_WithTargetClient_ShowsAliasInConsoleAndUploadMachineNameInUploadedLog()
    {
        var encryptedResult = new CommandResult
        {
            CommandId = "CMD-TARGET-1",
            IsEncrypted = true,
            EncryptedPayload = "ENCRYPTED_BLOB_BASE64"
        };

        var (client, state, crypto) = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(encryptedResult)
        }));

        crypto.OnDecryptResult = (cmdId, blob) => Task.FromResult(
            "{\"Success\":true,\"DurationMs\":10.0,\"Output\":\"Target client output\",\"Error\":\"\",\"CombinedOutput\":\"Target client output\"}");

        var targetClient = new InspiredCodes.RemotePulse.App.Models.PairedClient
        {
            MachineId = "abcdef12-3456-7890-abcd-ef1234567890",
            Alias = "Bombus"
        };

        await client.PollCommandResultAsync(HubUrl, "CMD-TARGET-1", timeoutSeconds: 5, targetClient);

        // Target client alias in console output
        Assert.Contains("=== Bombus · Command [CMD-TARGET-1] Result", state.ConsoleOutput);

        // Upload machine name in diagnostic output (never the alias)
        Assert.Contains("=== machine abcdef12 · Command [CMD-TARGET-1] Result", state.DiagnosticOutput);
        Assert.DoesNotContain("Bombus", state.DiagnosticOutput);
    }
}

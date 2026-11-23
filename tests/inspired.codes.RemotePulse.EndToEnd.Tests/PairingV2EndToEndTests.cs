using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using InspiredCodes.RemotePulse.App.Models;
using InspiredCodes.RemotePulse.App.Services;
using InspiredCodes.RemotePulse.HubServer.Data;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using Xunit;
using PairingPage = InspiredCodes.RemotePulse.App.Pages.Pairing;

namespace InspiredCodes.RemotePulse.EndToEnd.Tests;

/// <summary>
/// End-to-end tests for Pairing v2 key binding (docs/specs/pairing-v2-key-binding-spec.md §6):
/// exercises the full Worker LocalUiServer → App PairingLinkParser + HubApiClient → Hub /api/pairing/v2
/// → Worker PollingWorker 5-part PAIRING announcement → encrypted PowerShell command round-trip,
/// plus the two malicious-Hub key-substitution cases.
/// </summary>
public class PairingV2EndToEndTests
{
    [Fact]
    public async Task PairingV2_FullRoundTrip_WorkerQrToAppSubmitToWorkerAnnounceToCommandExecution()
    {
        var ct = TestContext.Current.CancellationToken;
        using var sut = new RemotePulseFixture();
        using var localUiServer = sut.CreateLocalUiServer();
        var workerLogger = new CapturingLogger<InspiredCodes.RemotePulse.Worker.PollingWorker>();

        // 1. Worker generates secret S on demand, stores (S, pid) in its ring, and pushes pid to Hub /api/pairing/v2
        var qrResult = await localUiServer.GenerateAndPushSecretAsync(ct);
        Assert.True(qrResult.Succeeded, $"Worker GenerateAndPushSecretAsync failed: {qrResult.Error}");
        Assert.Contains("/pairing/v2#k=", qrResult.PairingUrl);

        // 2. App scans and parses the Worker's v2 QR link
        Assert.True(PairingLinkParser.TryParse(qrResult.PairingUrl, out var parsedLink));
        Assert.Equal(2, parsedLink.Version);
        Assert.NotNull(parsedLink.WorkerFingerprint);

        // 3. App submits its half via HubApiClient.SubmitCoPresenceAsync (derives pid & AppBindTag, verifies Worker fp)
        var (hubApi, appState) = CreateAppClient(sut);
        var submitResult = await hubApi.SubmitCoPresenceAsync(
            parsedLink.HubOrigin,
            parsedLink.Secret,
            parsedLink.WorkerFingerprint!,
            parsedLink.GeneratedAtUtc);

        Assert.Equal(PairingSubmitResult.Paired, submitResult);
        var pairedClient = Assert.Single(appState.PairedClients);
        Assert.Equal(sut.MachineId, pairedClient.MachineId);
        Assert.Equal(sut.WorkerKeys.GetPublicKeyBase64(), pairedClient.PublicKey);
        Assert.Equal(sut.WorkerKeys.GetPublicKeyBase64(), hubApi.LastPairedClientPublicKey);

        // 4. Worker polls /api/commands/poll, receives 5-part PAIRING announcement, verifies AppBindTag, and writes pairing.json
        string pairingFilePath = Path.Combine(sut.DataDirectory, "pairing.json");
        Assert.False(File.Exists(pairingFilePath));

        await sut.RunWorkerCycleAsync(localUiServer: localUiServer, workerLogger: workerLogger);

        Assert.True(File.Exists(pairingFilePath));
        Assert.Contains(workerLogger.Messages, m => m.Contains("Pairing confirmed via co-presence"));

        // Verify both App and Worker compute the exact same 6-digit SAS
        string appSas = PairingCrypto.ComputeSafetyCode(hubApi.LastPairedClientPublicKey!, appState.AppPublicKeyBase64);
        string workerSas = PairingCrypto.ComputeSafetyCode(sut.WorkerKeys.GetPublicKeyBase64(), sut.AppPublicKeyBase64);
        Assert.Equal(appSas, workerSas);
        Assert.Matches(@"^\d{3} \d{3}$", appSas);

        // 5. Queue a real signed & hybrid-encrypted PowerShell command and execute it on the newly paired Worker
        string commandId = await sut.QueueCommandAsync(
            "Write-Output 'PAIRED-V2-E2E-4711'",
            ExecutionMode.RunWithHighestLocalPrivileges);

        await sut.RunWorkerCycleAsync(localUiServer: localUiServer, workerLogger: workerLogger);

        var decrypted = await sut.GetDecryptedResultAsync(commandId);
        Assert.NotNull(decrypted);
        Assert.True(decrypted!.Success, $"Expected command to succeed after v2 pairing. Error: {decrypted.Error}");
        Assert.Contains("PAIRED-V2-E2E-4711", decrypted.Output);
    }

    [Fact]
    public async Task MaliciousHub_SwapsClientPublicKeyInMatchedResponse_AppAbortsAndDoesNotSaveClient()
    {
        var ct = TestContext.Current.CancellationToken;
        using var sut = new RemotePulseFixture();
        using var localUiServer = sut.CreateLocalUiServer();

        // 1. Worker generates v2 QR link and pushes (pid, MachineId, RealWorkerPublicKey) to Hub
        var qrResult = await localUiServer.GenerateAndPushSecretAsync(ct);
        Assert.True(qrResult.Succeeded);
        Assert.True(PairingLinkParser.TryParse(qrResult.PairingUrl, out var parsedLink));

        string pid = PairingCrypto.DerivePairingId(parsedLink.Secret);

        // 2. Malicious Hub swaps ClientPublicKey in PendingCoPresences to an attacker-controlled keypair
        using var attackerWorkerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string attackerWorkerPublicKey = Convert.ToBase64String(attackerWorkerKey.ExportSubjectPublicKeyInfo());
        using (var scope = sut.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            var pending = await db.PendingCoPresences.SingleAsync(p => p.PairingId == pid, ct);
            pending.ClientPublicKey = attackerWorkerPublicKey;
            await db.SaveChangesAsync(ct);
        }

        // 3. App submits to /api/pairing/v2; Hub returns the swapped ClientPublicKey in the matched response
        var (hubApi, appState) = CreateAppClient(sut);
        var submitResult = await hubApi.SubmitCoPresenceAsync(
            parsedLink.HubOrigin,
            parsedLink.Secret,
            parsedLink.WorkerFingerprint!,
            parsedLink.GeneratedAtUtc);

        // 4. App detects the SPKI fingerprint mismatch, aborts locally, and never saves the client
        Assert.Equal(PairingSubmitResult.FingerprintMismatch, submitResult);
        Assert.Empty(appState.PairedClients);
        Assert.Null(hubApi.LastPairedClientPublicKey);
        Assert.Contains(PairingPage.FingerprintMismatchErrorMessage, appState.ConsoleOutput);
    }

    [Fact]
    public async Task MaliciousHub_SwapsAppPublicKeyInPairingsRow_WorkerRejectsAnnouncementAndDoesNotPair()
    {
        var ct = TestContext.Current.CancellationToken;
        using var sut = new RemotePulseFixture();
        using var localUiServer = sut.CreateLocalUiServer();
        var workerLogger = new CapturingLogger<InspiredCodes.RemotePulse.Worker.PollingWorker>();

        // 1. Worker generates v2 QR link and App completes its submission normally
        var qrResult = await localUiServer.GenerateAndPushSecretAsync(ct);
        Assert.True(qrResult.Succeeded);
        Assert.True(PairingLinkParser.TryParse(qrResult.PairingUrl, out var parsedLink));

        var (hubApi, _) = CreateAppClient(sut);
        var submitResult = await hubApi.SubmitCoPresenceAsync(
            parsedLink.HubOrigin,
            parsedLink.Secret,
            parsedLink.WorkerFingerprint!,
            parsedLink.GeneratedAtUtc);
        Assert.Equal(PairingSubmitResult.Paired, submitResult);

        // 2. Before Worker polls, malicious Hub swaps AppPublicKey in the Pairings row to an attacker's key
        using var attackerAppEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string attackerAppPublicKey = Convert.ToBase64String(attackerAppEcdsa.ExportSubjectPublicKeyInfo());
        using (var scope = sut.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            var pairing = await db.Pairings.SingleAsync(p => p.MachineId == sut.MachineId && p.AppId == sut.AppId, ct);
            pairing.AppPublicKey = attackerAppPublicKey;
            await db.SaveChangesAsync(ct);
        }

        // 3. Worker polls /api/commands/poll, receives 5-part PAIRING announcement with swapped AppPublicKey,
        //    verifies AppBindTag against its secret ring, and rejects the announcement
        string pairingFilePath = Path.Combine(sut.DataDirectory, "pairing.json");
        await sut.RunWorkerCycleAsync(localUiServer: localUiServer, workerLogger: workerLogger);

        Assert.False(File.Exists(pairingFilePath));
        Assert.Contains(workerLogger.Messages, m => m.Contains("PAIRING announcement rejected: invalid AppBindTag"));
        Assert.DoesNotContain(workerLogger.Messages, m => m.Contains("Pairing confirmed via co-presence"));
    }

    private static (HubApiClient HubApi, AppState State) CreateAppClient(RemotePulseFixture sut)
    {
        var js = new EcdsaSigningJSRuntime(sut.AppKeys);
        var crypto = new CryptoService(js);
        var state = new AppState(new LocalStorageService(js), crypto)
        {
            AppId = sut.AppId,
            AppPublicKeyBase64 = sut.AppPublicKeyBase64,
            ServerUrl = "http://localhost"
        };
        var hubApi = new HubApiClient(sut.HubClient, state, crypto);
        return (hubApi, state);
    }

    private sealed class EcdsaSigningJSRuntime(ECDsa appKeys) : IJSRuntime
    {
        private readonly Dictionary<string, string> _storage = new();

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
            => InvokeAsync<TValue>(identifier, CancellationToken.None, args);

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        {
            object? result = identifier switch
            {
                "localStorage.getItem" => _storage.TryGetValue((string)args![0]!, out var val) ? val : null,
                "localStorage.setItem" => SetItem((string)args![0]!, (string)args[1]!),
                "localStorage.removeItem" => _storage.Remove((string)args![0]!),
                "qrScannerInterop.signMessage" => Convert.ToBase64String(
                    appKeys.SignData(
                        Encoding.UTF8.GetBytes((string)args![1]!),
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
                _ => throw new NotSupportedException($"Unexpected JS interop call: {identifier}")
            };
            return new ValueTask<TValue>((TValue)result!);
        }

        private object? SetItem(string key, string value)
        {
            _storage[key] = value;
            return null;
        }
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Add($"[{logLevel}] {formatter(state, exception)}");
        }
    }
}

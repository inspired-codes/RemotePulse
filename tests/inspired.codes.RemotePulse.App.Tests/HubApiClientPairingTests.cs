using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using InspiredCodes.RemotePulse.App.Models;
using InspiredCodes.RemotePulse.App.Pages;
using InspiredCodes.RemotePulse.App.Services;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

/// <summary>
/// Covers <see cref="HubApiClient.SubmitCoPresenceAsync"/> for Pairing v2 key binding:
/// verifies that the request body sends <c>pairingId</c> and <c>appBindTag</c> (never the raw
/// secret <c>S</c>), verifies the Worker public-key fingerprint before saving, and maps
/// over-limit pairings onto <see cref="PairingSubmitResult.PairedOverLimit"/>.
/// </summary>
public class HubApiClientPairingTests
{
    private const string HubUrl = "https://hub.example.test";

    private static (string PublicKeyBase64, string Fingerprint) CreateWorkerKeyAndFingerprint()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string pubKey = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
        string fp = PairingCrypto.ComputePublicKeyFingerprint(pubKey);
        return (pubKey, fp);
    }

    [Fact]
    public async Task SubmitCoPresenceAsync_UnderLimit_VerifiesFingerprintAndNeverSendsSecret()
    {
        var (workerPubKey, workerFp) = CreateWorkerKeyAndFingerprint();
        string secret = PairingCrypto.GenerateSecret();
        string expectedPid = PairingCrypto.DerivePairingId(secret);

        string? capturedUrl = null;
        string? capturedBody = null;
        var sut = Build(async req =>
        {
            capturedUrl = req.RequestUri?.ToString();
            capturedBody = await req.Content!.ReadAsStringAsync();
            return await Json(HttpStatusCode.OK, new { machineId = "PC-1", clientPublicKey = workerPubKey });
        });

        var result = await sut.HubApi.SubmitCoPresenceAsync(HubUrl, secret, workerFp, DateTimeOffset.UtcNow);

        Assert.Equal(PairingSubmitResult.Paired, result);
        Assert.Single(sut.State.PairedClients);
        Assert.Equal(workerPubKey, sut.State.PairedClients[0].PublicKey);

        Assert.Equal($"{HubUrl}/api/pairing/v2", capturedUrl);
        Assert.NotNull(capturedBody);
        Assert.DoesNotContain(secret, capturedBody!);

        using var doc = JsonDocument.Parse(capturedBody!);
        Assert.Equal(expectedPid, doc.RootElement.GetProperty("pairingId").GetString());
        string expectedTag = PairingCrypto.ComputeAppBindTag(secret, expectedPid, workerFp, sut.State.AppId, sut.State.AppPublicKeyBase64);
        Assert.Equal(expectedTag, doc.RootElement.GetProperty("appBindTag").GetString());
    }

    [Fact]
    public async Task SubmitCoPresenceAsync_FingerprintMismatch_AbortsWithoutSavingAndSendsNoFurtherRequest()
    {
        var (_, expectedWorkerFp) = CreateWorkerKeyAndFingerprint();
        var (swappedWorkerPubKey, _) = CreateWorkerKeyAndFingerprint();
        string secret = PairingCrypto.GenerateSecret();

        int requestCount = 0;
        var sut = Build(_ =>
        {
            requestCount++;
            return Json(HttpStatusCode.OK, new { machineId = "PC-1", clientPublicKey = swappedWorkerPubKey });
        });

        var result = await sut.HubApi.SubmitCoPresenceAsync(HubUrl, secret, expectedWorkerFp, DateTimeOffset.UtcNow);

        Assert.Equal(PairingSubmitResult.FingerprintMismatch, result);
        Assert.Empty(sut.State.PairedClients);
        Assert.Equal(1, requestCount); // No release or follow-up call sent to the Hub
        Assert.Contains(Pairing.FingerprintMismatchErrorMessage, sut.State.ConsoleOutput);
    }

    [Fact]
    public async Task SubmitCoPresenceAsync_PastLimit_StillPairs_ReturnsPairedOverLimit()
    {
        var (workerPubKey, workerFp) = CreateWorkerKeyAndFingerprint();
        string secret = PairingCrypto.GenerateSecret();
        var sut = Build(_ => Json(HttpStatusCode.OK, new { machineId = "PC-4", clientPublicKey = workerPubKey }),
            existingPairedCount: 3);

        var result = await sut.HubApi.SubmitCoPresenceAsync(HubUrl, secret, workerFp, DateTimeOffset.UtcNow);

        Assert.Equal(PairingSubmitResult.PairedOverLimit, result);
        Assert.Equal(4, sut.State.PairedClients.Count);
        Assert.Contains(sut.State.PairedClients, c => c.MachineId == "PC-4");
    }

    [Fact]
    public async Task SubmitCoPresenceAsync_RePairingExistingMachine_PastLimit_ReturnsPaired_NotOverLimit()
    {
        var (workerPubKey, workerFp) = CreateWorkerKeyAndFingerprint();
        string secret = PairingCrypto.GenerateSecret();
        var sut = Build(_ => Json(HttpStatusCode.OK, new { machineId = "PC-2", clientPublicKey = workerPubKey }),
            existingPairedCount: 4);

        var result = await sut.HubApi.SubmitCoPresenceAsync(HubUrl, secret, workerFp, DateTimeOffset.UtcNow);

        // Already over the limit before this call, but it's a re-pair of an existing machine -
        // Updated, not AddedOverLimit, so this must not read as a fresh over-limit event.
        Assert.Equal(PairingSubmitResult.Paired, result);
        Assert.Equal(4, sut.State.PairedClients.Count);
    }

    [Fact]
    public async Task SubmitCoPresenceAsync_HubRejects_ReturnsFailed_NothingStored()
    {
        var (_, workerFp) = CreateWorkerKeyAndFingerprint();
        string secret = PairingCrypto.GenerateSecret();
        var sut = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("pairing code expired")
        }));

        var result = await sut.HubApi.SubmitCoPresenceAsync(HubUrl, secret, workerFp, DateTimeOffset.UtcNow);

        Assert.Equal(PairingSubmitResult.Failed, result);
        Assert.Empty(sut.State.PairedClients);
    }

    private static Task<HttpResponseMessage> Json(HttpStatusCode status, object payload)
        => Task.FromResult(new HttpResponseMessage(status) { Content = JsonContent.Create(payload) });

    private static Harness Build(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond, int existingPairedCount = 0)
    {
        var js = new FakeJSRuntime();
        var state = new AppState(new LocalStorageService(js), new CryptoService(js))
        {
            AppId = Guid.NewGuid().ToString(),
            AppPublicKeyBase64 = "app-pub-key"
        };

        for (int i = 1; i <= existingPairedCount; i++)
        {
            string machineId = $"PC-{i}";
            state.PairedClients.Add(new PairedClient { MachineId = machineId, PublicKey = $"pub-{i}", ServerUrl = HubUrl, Alias = machineId });
        }

        var handler = new MockHttpMessageHandler(respond);
        var hubApi = new HubApiClient(new HttpClient(handler), state, new CryptoService(js));

        return new Harness(hubApi, state);
    }

    private sealed record Harness(HubApiClient HubApi, AppState State);
}

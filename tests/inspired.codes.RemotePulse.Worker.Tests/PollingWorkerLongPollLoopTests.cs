using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using InspiredCodes.Client.PowerShellEngine;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using Xunit;

namespace InspiredCodes.RemotePulse.Worker.Tests;

/// <summary>
/// Covers the long-polling loop itself rather than a single cycle. The loop deliberately has no
/// timer - it relies on the Hub holding each request open to pace it - so what happens when the
/// Hub does *not* hold the request open is the interesting case, and the one a per-cycle test
/// can never reach.
/// </summary>
public class PollingWorkerLongPollLoopTests : IDisposable
{
    private readonly string _dataDirectory;
    private readonly KeyPairManager _keyManager;
    private readonly string _machineId = Guid.NewGuid().ToString();
    private readonly TestPowerShellEngine _psEngine = new();
    private readonly ECDsa _appEcdsa;

    public PollingWorkerLongPollLoopTests()
    {
        _dataDirectory = Path.Combine(Path.GetTempPath(), $"remotepulse_loop_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dataDirectory);

        _keyManager = new KeyPairManager(Path.Combine(_dataDirectory, "client_key.dat"));
        _keyManager.GenerateAndSaveKeys();

        _appEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(
            Path.Combine(_dataDirectory, "pairing.json"),
            JsonSerializer.Serialize(new[]
            {
                new { AppId = "TEST-APP-999", AppPublicKey = Convert.ToBase64String(_appEcdsa.ExportSubjectPublicKeyInfo()) }
            }));
    }

    /// <summary>
    /// An older Hub, or one behind a proxy that strips the query string, answers a long poll
    /// immediately with 204 instead of parking it. Nothing throws, so the loop's exception
    /// backoff never fires - the poll interval has to be what stops this becoming a tight loop.
    /// </summary>
    [Fact]
    public async Task AHubThatIgnoresTheWaitWindowShouldNotProduceATightPollingLoop()
    {
        int requests = 0;
        var handler = new MockHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref requests);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        });

        await RunLoopAsync(handler, pollIntervalSeconds: 2, longPollWaitSeconds: 30, runFor: TimeSpan.FromSeconds(5));

        // Paced at 2s the loop manages a startup poll plus a handful more. Unpaced it manages
        // thousands, so the two outcomes are never within an order of magnitude of each other.
        Assert.InRange(requests, 1, 8);
    }

    /// <summary>The same hazard with the Hub simply down, which is the likelier way to meet it.</summary>
    [Fact]
    public async Task AnUnreachableHubShouldNotProduceATightPollingLoop()
    {
        int requests = 0;
        var handler = new MockHttpMessageHandler(_ =>
        {
            Interlocked.Increment(ref requests);
            throw new HttpRequestException("Connection refused");
        });

        await RunLoopAsync(handler, pollIntervalSeconds: 2, longPollWaitSeconds: 30, runFor: TimeSpan.FromSeconds(5));

        Assert.InRange(requests, 1, 8);
    }

    /// <summary>
    /// The other half of the contract: pacing must apply only to idle cycles. When commands are
    /// waiting, the loop has to come straight back for the next one - making the operator wait a
    /// poll interval for the second of two commands is the latency long-polling exists to remove.
    /// </summary>
    [Fact]
    public async Task ACycleThatHandledWorkShouldReconnectImmediately()
    {
        int polls = 0;
        string encrypted = EncryptCommandForWorker("Get-Process");

        var handler = new MockHttpMessageHandler(request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }

            Interlocked.Increment(ref polls);
            var payload = new ServerCommand
            {
                CommandId = "CMD-LOOP",
                Script = encrypted,
                ExecutionMode = ExecutionMode.RunAsCurrentUser
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(payload, options: new JsonSerializerOptions(JsonSerializerDefaults.Web)
                {
                    Converters = { new JsonStringEnumConverter() }
                })
            });
        });

        _psEngine.ResultToReturn = new PowerShellResult
        {
            MachineId = _machineId,
            Success = true,
            Output = "ok",
            CombinedOutput = "ok"
        };

        // A 30s floor: if work were paced like idleness, only the startup poll would get through.
        await RunLoopAsync(handler, pollIntervalSeconds: 30, longPollWaitSeconds: 30, runFor: TimeSpan.FromSeconds(3));

        Assert.True(polls > 5, $"Expected the loop to keep pulling queued work; it polled {polls} time(s).");
    }

    private async Task RunLoopAsync(HttpMessageHandler handler, int pollIntervalSeconds, int longPollWaitSeconds, TimeSpan runFor)
    {
        var worker = new PollingWorker(
            new TestLogger<PollingWorker>(),
            new TestHttpClientFactory(handler),
            _keyManager,
            _psEngine,
            _machineId,
            pollIntervalSeconds,
            new TestLogger<LocalUiServer>(),
            "http://localhost/",
            dataDirectory: _dataDirectory,
            localUiPort: 0,
            longPollWaitSeconds: longPollWaitSeconds);

        await worker.StartAsync(CancellationToken.None);
        await Task.Delay(runFor);
        await worker.StopAsync(CancellationToken.None);
    }

    private string EncryptCommandForWorker(string script)
    {
        string signature = Convert.ToBase64String(_appEcdsa.SignData(
            Encoding.UTF8.GetBytes(script), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        string envelope = JsonSerializer.Serialize(new { Script = script, Signature = signature });
        return Convert.ToBase64String(HybridCrypto.Encrypt(Encoding.UTF8.GetBytes(envelope), _keyManager.GetPublicKeyBase64()));
    }

    public void Dispose()
    {
        _keyManager.Dispose();
        _appEcdsa.Dispose();
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

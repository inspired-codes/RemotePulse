using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using InspiredCodes.Client.PowerShellEngine;
using InspiredCodes.RemotePulse.HubServer.Data;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using InspiredCodes.RemotePulse.Worker;
using HubProgram = InspiredCodes.RemotePulse.HubServer.Program;
// Disambiguated from the InspiredCodes.Client namespace, which otherwise shadows the entity name.
using ClientEntity = InspiredCodes.RemotePulse.HubServer.Data.Client;

namespace InspiredCodes.RemotePulse.EndToEnd.Tests;

/// <summary>
/// Wires a real Hub, a real Worker, and the real PowerShell engine together inside one test
/// process, so the whole App → Hub → Worker → PowerShell → Hub → App round trip can be exercised
/// without installing a service, running a database, or touching the machine's shared state.
/// </summary>
/// <remarks>
/// Nothing here is a stand-in for production behavior except the transport: the Hub runs in
/// memory via <see cref="WebApplicationFactory{T}"/>, and the Worker reaches it through an
/// <see cref="IHttpClientFactory"/> whose clients are that test server's. Signing, hybrid
/// encryption, signature verification, and script execution are all the genuine implementations.
///
/// The Worker's data directory and Local UI port are both redirected (temp folder, ephemeral
/// port) so a test run never collides with an installed RemotePulse Worker service.
/// </remarks>
public sealed class RemotePulseFixture : IDisposable
{
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly WebApplicationFactory<HubProgram> _factory;
    private readonly string _dataDirectory;

    /// <summary>The Worker's identity and keypair.</summary>
    public string MachineId { get; }
    public KeyPairManager WorkerKeys { get; }

    /// <summary>The App's identity and signing key (the PWA's ECDSA P-256 keypair).</summary>
    public string AppId { get; }
    public ECDsa AppKeys { get; }
    public Dictionary<string, byte[]> ReplyKeys { get; } = new();

    public HttpClient HubClient => _factory.CreateClient();
    public IServiceProvider Services => _factory.Services;
    public string DataDirectory => _dataDirectory;

    public RemotePulseFixture()
    {
        string dbName = $"InMemory_E2E_{Guid.NewGuid():N}";
        _factory = new WebApplicationFactory<HubProgram>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", dbName },
                    { "RateLimiting:PairingPermitsPerMinute", "1000" }
                });
            });
        });

        _dataDirectory = Path.Combine(Path.GetTempPath(), $"remotepulse_e2e_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dataDirectory);

        MachineId = Guid.NewGuid().ToString();
        WorkerKeys = new KeyPairManager(Path.Combine(_dataDirectory, "client_key.dat"));
        WorkerKeys.GenerateAndSaveKeys();

        AppId = Guid.NewGuid().ToString();
        AppKeys = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    /// <summary>
    /// Puts the Hub and the Worker into the state they'd be in after a completed pairing: the
    /// machine registered with its public key, a locked pairing to this App, and the Worker's
    /// local pairing.json listing the App's key so it will accept that App's signatures.
    /// </summary>
    public async Task PairAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();

        string secret = PairingCrypto.GenerateSecret();
        string pid = PairingCrypto.DerivePairingId(secret);
        string workerFp = PairingCrypto.ComputePublicKeyFingerprint(WorkerKeys.GetPublicKeyBase64());
        string appBindTag = PairingCrypto.ComputeAppBindTag(secret, pid, workerFp, AppId, AppPublicKeyBase64);

        db.Clients.Add(new ClientEntity
        {
            MachineId = MachineId,
            PublicKey = WorkerKeys.GetPublicKeyBase64()
        });
        db.Pairings.Add(new Pairing
        {
            MachineId = MachineId,
            AppId = AppId,
            AppPublicKey = AppPublicKeyBase64,
            PairingId = pid,
            AppBindTag = appBindTag,
            IsLocked = true,
            AnnouncedToClientAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        WriteWorkerPairingFile(AppId, AppPublicKeyBase64);
    }

    /// <summary>
    /// Creates a real <see cref="LocalUiServer"/> wired to the in-memory Hub so tests can exercise
    /// the Worker's QR generation and secret ring end-to-end without binding a TCP listener.
    /// </summary>
    public LocalUiServer CreateLocalUiServer(ILogger<LocalUiServer>? logger = null)
    {
        return new LocalUiServer(
            logger ?? NullLogger<LocalUiServer>.Instance,
            WorkerKeys,
            new TestServerHttpClientFactory(_factory),
            MachineId,
            serverUrl: "http://localhost/",
            port: 0);
    }

    public string AppPublicKeyBase64 => Convert.ToBase64String(AppKeys.ExportSubjectPublicKeyInfo());

    /// <summary>Writes the Worker's local pairing.json, the list of App keys it will trust.</summary>
    public void WriteWorkerPairingFile(string appId, string appPublicKeyBase64)
    {
        string path = Path.Combine(_dataDirectory, "pairing.json");
        string json = JsonSerializer.Serialize(new[] { new { AppId = appId, AppPublicKey = appPublicKeyBase64 } });
        File.WriteAllText(path, json);
    }

    /// <summary>
    /// Does what the PWA does when you press Execute: signs the script, hybrid-encrypts the
    /// envelope to the Worker's public key, and queues it on the Hub with App signature headers.
    /// </summary>
    /// <param name="signingKey">
    /// Defaults to this App's real key. Pass a different one to simulate a forged command.
    /// </param>
    public async Task<string> QueueCommandAsync(string script, ExecutionMode executionMode, ECDsa? signingKey = null, int? timeoutSeconds = null)
    {
        signingKey ??= AppKeys;
        string commandId = "CMD-" + Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
        string issuedAtUtc = DateTime.UtcNow.ToString("o");
        string nonce = Guid.NewGuid().ToString("N");

        byte[] replyKey = RandomNumberGenerator.GetBytes(32);
        ReplyKeys[commandId] = replyKey;
        string replyKeyBase64 = Convert.ToBase64String(replyKey);

        string payloadToSign = $"{commandId}:{(int)executionMode}:{timeoutSeconds ?? 0}:{issuedAtUtc}:{nonce}:{script}";
        byte[] payloadBytes = Encoding.UTF8.GetBytes(payloadToSign);
        string signature = Convert.ToBase64String(
            signingKey.SignData(payloadBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        string envelope = JsonSerializer.Serialize(new
        {
            CommandId = commandId,
            ExecutionMode = executionMode,
            TimeoutSeconds = timeoutSeconds,
            IssuedAtUtc = issuedAtUtc,
            Nonce = nonce,
            Script = script,
            Signature = signature,
            ReplyKey = replyKeyBase64
        });
        string encrypted = Convert.ToBase64String(
            HybridCrypto.Encrypt(Encoding.UTF8.GetBytes(envelope), WorkerKeys.GetPublicKeyBase64()));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/commands/queue");
        AddAppSignatureHeaders(request);
        request.Content = JsonContent.Create(new
        {
            MachineId,
            EncryptedScript = encrypted,
            ExecutionMode = executionMode,
            CommandId = commandId,
            TimeoutSeconds = timeoutSeconds
        }, options: JsonOptions);

        using var client = HubClient;
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        return commandId;
    }

    /// <summary>
    /// Runs the Worker for real: one full poll cycle that fetches the queued command, decrypts
    /// it, verifies the App signature, executes it through the genuine PowerShell engine, and
    /// posts the result back to the Hub.
    /// </summary>
    /// <param name="longPollWaitSeconds">
    /// When above zero the Worker asks the Hub to hold the poll open, so a command queued after
    /// the cycle starts is still picked up by it.
    /// </param>
    public async Task RunWorkerCycleAsync(
        int longPollWaitSeconds = 0,
        LocalUiServer? localUiServer = null,
        ILogger<PollingWorker>? workerLogger = null)
    {
        var worker = new PollingWorker(
            workerLogger ?? NullLogger<PollingWorker>.Instance,
            new TestServerHttpClientFactory(_factory),
            WorkerKeys,
            new PowerShellEngine(MachineId),
            MachineId,
            pollIntervalSeconds: 30,
            NullLogger<LocalUiServer>.Instance,
            serverUrl: "http://localhost/",
            dataDirectory: _dataDirectory,
            localUiPort: 0,
            longPollWaitSeconds: longPollWaitSeconds,
            localUiServer: localUiServer);

        // PollAndExecuteAsync is the unit of work a timer tick performs. Invoking it directly
        // keeps the test deterministic - no waiting on a background timer, and no Local UI.
        var method = typeof(PollingWorker).GetMethod(
            "PollAndExecuteAsync",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        if (method == null)
        {
            throw new InvalidOperationException("PollingWorker.PollAndExecuteAsync not found - was it renamed?");
        }

        await (Task)method.Invoke(worker, new object[] { CancellationToken.None })!;
    }

    /// <summary>Fetches a command's result as the App would, or null if none has been posted.</summary>
    public async Task<CommandResult?> GetResultAsync(string commandId)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/commands/results/{commandId}");
        AddAppSignatureHeaders(request);

        using var client = HubClient;
        var response = await client.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }
        return await response.Content.ReadFromJsonAsync<CommandResult>(JsonOptions);
    }

    /// <summary>Fetches and decrypts a command's result as the App would.</summary>
    public async Task<CommandResultPayload?> GetDecryptedResultAsync(string commandId)
    {
        var rawResult = await GetResultAsync(commandId);
        if (rawResult == null || !rawResult.IsEncrypted || string.IsNullOrEmpty(rawResult.EncryptedPayload))
        {
            return null;
        }

        if (!ReplyKeys.TryGetValue(commandId, out var replyKey))
        {
            throw new InvalidOperationException($"No reply key recorded for command {commandId}");
        }

        byte[] rawBlob = Convert.FromBase64String(rawResult.EncryptedPayload);
        byte[] nonce = rawBlob[..12];
        byte[] cipherAndTag = rawBlob[12..];
        byte[] cipher = cipherAndTag[..^16];
        byte[] tag = cipherAndTag[^16..];
        byte[] plain = new byte[cipher.Length];

        using var aesGcm = new AesGcm(replyKey, 16);
        aesGcm.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(commandId));

        string json = Encoding.UTF8.GetString(plain);
        return JsonSerializer.Deserialize<CommandResultPayload>(json, JsonOptions);
    }

    /// <summary>Reads the watchdog feed as the App's ClientWatchdog would.</summary>
    public async Task<List<ClientStatus>> GetClientStatusesAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/clients/status");
        AddAppSignatureHeaders(request);

        using var client = HubClient;
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<List<ClientStatus>>(JsonOptions) ?? new();
    }

    /// <summary>Reads back the poll interval the Worker self-reported via X-Poll-Interval.</summary>
    public async Task<int?> GetStoredPollIntervalAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        var client = await db.Clients.FirstAsync(c => c.MachineId == MachineId);
        return client.PollIntervalSeconds;
    }

    private void AddAppSignatureHeaders(HttpRequestMessage request)
    {
        string timestamp = DateTimeOffset.UtcNow.ToString("o");
        string nonce = Guid.NewGuid().ToString("N");
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
        byte[] message = Encoding.UTF8.GetBytes($"{method}:{path}:{AppId}:{timestamp}:{nonce}");
        string signature = Convert.ToBase64String(
            AppKeys.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        request.Headers.Add("X-App-Id", AppId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Signature", signature);
    }

    public void Dispose()
    {
        AppKeys.Dispose();
        WorkerKeys.Dispose();
        _factory.Dispose();

        try
        {
            if (Directory.Exists(_dataDirectory))
            {
                Directory.Delete(_dataDirectory, recursive: true);
            }
        }
        catch { }
    }

    /// <summary>
    /// Hands the Worker HttpClients wired to the in-memory Hub. A fresh one per call because
    /// PollingWorker disposes each client it takes.
    /// </summary>
    private sealed class TestServerHttpClientFactory(WebApplicationFactory<HubProgram> factory) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => factory.CreateClient();
    }
}

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using InspiredCodes.RemotePulse.Shared.Contracts;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using Xunit;

namespace InspiredCodes.RemotePulse.Worker.Tests;

/// <summary>
/// Covers LocalUiServer's co-presence secret generation/push loop (see
/// docs/specs/pairing-v2-key-binding-spec.md). The full 30-second rotation cadence isn't exercised here with real
/// wall-clock waits - that's covered by the real-machine verification task instead. This just
/// confirms the loop starts, pushes a correctly-shaped secret to the Hub immediately, and stops
/// cleanly.
/// </summary>
public class LocalUiServerTests : IDisposable
{
    private readonly string _tempKeyPath;
    private readonly KeyPairManager _keyManager;
    private readonly string _machineId;
    private readonly TestLogger<LocalUiServer> _logger;

    public LocalUiServerTests()
    {
        _tempKeyPath = Path.Combine(Path.GetTempPath(), $"localui_test_{Guid.NewGuid():N}.dat");
        _keyManager = new KeyPairManager(_tempKeyPath);
        _keyManager.GenerateAndSaveKeys();
        _machineId = Guid.NewGuid().ToString();
        _logger = new TestLogger<LocalUiServer>();
    }

    [Fact]
    public async Task GeneratePairingSecretAsync_ShouldPushAPairingIdShapedForRoleClient_AndNeverSendSecretToHub()
    {
        // Arrange
        string? capturedPath = null;
        string? capturedBody = null;
        var handlerReady = new SemaphoreSlim(0);
        MockHttpMessageHandler handler = new MockHttpMessageHandler(async request =>
        {
            capturedPath = request.RequestUri?.AbsolutePath;
            capturedBody = await request.Content!.ReadAsStringAsync();
            handlerReady.Release();
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "http://localhost:5000/", port: 0);

        try
        {
            // Act
            await server.StartAsync();
            var result = await server.GenerateAndPushSecretAsync();

            Assert.True(result.Succeeded, "Expected GenerateAndPushSecretAsync to succeed.");
            bool pushed = await handlerReady.WaitAsync(TimeSpan.FromSeconds(5));

            // Assert
            Assert.True(pushed, "Expected a Pairing v2 push to Hub.");
            Assert.Equal("/api/pairing/v2", capturedPath);
            Assert.NotNull(capturedBody);

            // Extract secret S and fp from the generated v2 QR URL
            Assert.Contains("http://localhost:5000/pairing/v2#k=", result.PairingUrl);
            var fragmentMatch = Regex.Match(result.PairingUrl, @"#k=([^&]+)&fp=([^&]+)&ts=");
            Assert.True(fragmentMatch.Success, $"Expected #k=...&fp=...&ts=... in {result.PairingUrl}");
            string secretInQr = Uri.UnescapeDataString(fragmentMatch.Groups[1].Value);
            string fpInQr = Uri.UnescapeDataString(fragmentMatch.Groups[2].Value);

            Assert.True(PairingCrypto.IsValidBase64Url256(secretInQr));
            Assert.Equal(PairingCrypto.ComputePublicKeyFingerprint(_keyManager.GetPublicKeyBase64()), fpInQr);

            // The Hub request body must NEVER contain S - only the HKDF-derived pid
            Assert.DoesNotContain(secretInQr, capturedBody!);

            using var doc = JsonDocument.Parse(capturedBody!);
            Assert.Equal("Client", doc.RootElement.GetProperty("role").GetString());
            Assert.Equal(_machineId, doc.RootElement.GetProperty("machineId").GetString());
            Assert.Equal(_keyManager.GetPublicKeyBase64(), doc.RootElement.GetProperty("publicKey").GetString());

            string pidInBody = doc.RootElement.GetProperty("pairingId").GetString()!;
            Assert.Equal(PairingCrypto.DerivePairingId(secretInQr), pidInBody);
            Assert.True(server.TryGetValidSecret(pidInBody, out string? ringSecret));
            Assert.Equal(secretInQr, ringSecret);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task OnboardingPage_ShouldServeGenerateButtonInitially_AndPairingLinkWhenActive()
    {
        var secretPushed = new SemaphoreSlim(0);
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ =>
        {
            secretPushed.Release();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();

            // 1. Initial GET / serves the button to generate a QR code
            string htmlInitial = await httpClient.GetStringAsync($"http://localhost:{server.Port}/");
            Assert.Contains("generateQrBtn", htmlInitial);
            Assert.Contains("Generate Pairing Code", htmlInitial);

            // 2. Generate secret on demand
            var (succeeded, _, pairingUrl, _) = await server.GenerateAndPushSecretAsync();
            Assert.True(succeeded);
            Assert.Contains("https://hub.example.test/pairing/v2#k=", pairingUrl);
            Assert.Contains("&fp=", pairingUrl);
            Assert.Contains("&ts=", pairingUrl);

            // 3. GET / now serves the active pairing link
            string htmlWithActive = await httpClient.GetStringAsync($"http://localhost:{server.Port}/");
            Assert.Contains("https://hub.example.test/pairing/v2#k=", htmlWithActive);
            Assert.Contains("&fp=", htmlWithActive);
            Assert.Contains("&ts=", htmlWithActive);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task StatusPage_ShouldDisplaySafetyCodeForPairedApp()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        const string appId = "app-sas-test";
        const string appPubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba=="; // gitleaks:allow (fake test key)
        string expectedSas = PairingCrypto.ComputeSafetyCode(_keyManager.GetPublicKeyBase64(), appPubKey);

        LocalUiServer server = new LocalUiServer(
            _logger,
            _keyManager,
            factory,
            _machineId,
            "https://hub.example.test/",
            pairedAppIds: new[] { appId },
            port: 0,
            pairedAppPublicKeys: new System.Collections.Generic.Dictionary<string, string> { [appId] = appPubKey });

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            string html = await httpClient.GetStringAsync($"http://localhost:{server.Port}/");

            Assert.Contains("Safety Code (SAS):", html);
            Assert.Contains(expectedSas, html);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task PairingGenerateEndpoint_TrustedOrigin_ReturnsSuccessAndPairingUrl()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://localhost:{server.Port}/api/pairing/generate");
            request.Headers.Add("Origin", $"http://localhost:{server.Port}");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            string body = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            Assert.True(doc.RootElement.GetProperty("success").GetBoolean());
            Assert.Equal(90, doc.RootElement.GetProperty("validitySeconds").GetInt32());
            string url = doc.RootElement.GetProperty("pairingUrl").GetString()!;
            Assert.Contains("https://hub.example.test/pairing/v2#k=", url);
            Assert.Contains("&fp=", url);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task ConfigEndpoint_UntrustedOrigin_ShouldReturnForbidden()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://localhost:{server.Port}/api/config");
            request.Headers.Add("Origin", $"http://localhost:{server.Port}.attacker.com");
            request.Content = JsonContent.Create(new { serverUrl = "https://evil.example.com/" });

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task SendLogEndpoint_TrustedOrigin_DispatchesSignedTelemetryToHub()
    {
        HttpRequestMessage? capturedHubRequest = null;
        string? capturedHubBody = null;
        var hubPostReceived = new SemaphoreSlim(0);

        MockHttpMessageHandler handler = new MockHttpMessageHandler(async request =>
        {
            if (request.RequestUri?.AbsolutePath.Contains("api/telemetry/logs") == true)
            {
                capturedHubRequest = request;
                capturedHubBody = await request.Content!.ReadAsStringAsync();
                hubPostReceived.Release();
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://localhost:{server.Port}/api/send-log");
            request.Headers.Add("Origin", $"http://localhost:{server.Port}");
            request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            bool receivedByHub = await hubPostReceived.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(receivedByHub, "Hub did not receive telemetry dispatch within timeout");

            Assert.NotNull(capturedHubRequest);
            Assert.Equal("api/telemetry/logs", capturedHubRequest.RequestUri?.AbsolutePath.TrimStart('/'));
            Assert.True(capturedHubRequest.Headers.Contains("X-Client-Id"));
            Assert.Equal(_machineId, capturedHubRequest.Headers.GetValues("X-Client-Id").First());
            Assert.True(capturedHubRequest.Headers.Contains("X-Signature"));
            Assert.True(capturedHubRequest.Headers.Contains("X-Timestamp"));
            Assert.True(capturedHubRequest.Headers.Contains("X-Nonce"));
            Assert.True(capturedHubRequest.Headers.Contains(ProtocolConstants.WorkerVersionHeaderName));
            Assert.Equal(PollingWorker.WorkerVersion, capturedHubRequest.Headers.GetValues(ProtocolConstants.WorkerVersionHeaderName).First());
            Assert.True(capturedHubRequest.Headers.Contains(ProtocolConstants.WorkerCapabilitiesHeaderName));
            Assert.Equal(string.Empty, capturedHubRequest.Headers.GetValues(ProtocolConstants.WorkerCapabilitiesHeaderName).First());

            Assert.NotNull(capturedHubBody);
            using JsonDocument doc = JsonDocument.Parse(capturedHubBody);
            Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
            var firstEntry = doc.RootElement[0];
            Assert.Equal("ManualWorkerLogUpload", firstEntry.GetProperty("eventName").GetString());
            Assert.Equal("Worker", firstEntry.GetProperty("source").GetString());
            Assert.Equal("LocalUiServer", firstEntry.GetProperty("category").GetString());
            Assert.Equal(_machineId, firstEntry.GetProperty("machineId").GetString());
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task SendLogEndpoint_UntrustedOrigin_ShouldReturnForbidden()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://localhost:{server.Port}/api/send-log");
            request.Headers.Add("Origin", $"http://attacker.com");
            request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task StatusPage_And_OnboardingPage_ShouldContainSendLogButton()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            string html = await httpClient.GetStringAsync($"http://localhost:{server.Port}/");

            Assert.Contains("Send Diagnostic Log to Hub", html);
            Assert.Contains("sendLog()", html);
            Assert.Contains("/api/send-log", html);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WorkerPage_ShowsTheRunningWorkerVersionInTheServiceBox(bool paired)
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        IReadOnlyList<string>? pairedAppIds = paired ? new[] { "app-under-test" } : null;
        string expectedVersion = typeof(LocalUiServer).Assembly.GetName().Version!.ToString(3);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", pairedAppIds, port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            string html = await httpClient.GetStringAsync($"http://localhost:{server.Port}/");

            Assert.Contains($"Version: {expectedVersion}", html);
            Assert.DoesNotContain("##WORKER_VERSION##", html);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WorkerPage_EveryInlineHandlerIsDefinedOnThatPage(bool paired)
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);
        IReadOnlyList<string>? pairedAppIds = paired ? new[] { "app-under-test" } : null;

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", pairedAppIds, port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            string html = await httpClient.GetStringAsync($"http://localhost:{server.Port}/");

            string[] handlers = Regex.Matches(html, @"on(?:click|change)=""(\w+)\(")
                .Select(m => m.Groups[1].Value)
                .Distinct()
                .ToArray();

            Assert.NotEmpty(handlers);
            foreach (string name in handlers)
            {
                Assert.True(Regex.IsMatch(html, $@"function\s+{name}\s*\("),
                    $"The {(paired ? "status" : "onboarding")} page calls {name}() but never defines it.");
            }
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task LogsEndpoint_TrustedOrigin_ShouldReturnLogs()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"http://localhost:{server.Port}/api/logs");
            request.Headers.Add("Origin", $"http://localhost:{server.Port}");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            string json = await response.Content.ReadAsStringAsync();
            Assert.Contains("logs", json);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task StatusEndpoint_TrustedOrigin_ShouldReturnStatus()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, $"http://localhost:{server.Port}/api/status");
            request.Headers.Add("Origin", $"http://localhost:{server.Port}");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            string json = await response.Content.ReadAsStringAsync();
            Assert.Contains("Running", json);
            Assert.Contains("hub.example.test", json);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task UI_ShouldContainStatusWidgets_And_ConsoleLogTail()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            string html = await httpClient.GetStringAsync($"http://localhost:{server.Port}/");

            Assert.Contains("Worker Service", html);
            Assert.Contains("Hub Connection", html);
            Assert.Contains("Connected Hub FQDN", html);
            Assert.Contains("Worker Console Log Tail", html);
            Assert.Contains("Validate &amp; Apply Server Address", html.Replace("&", "&amp;")); // Handle potential HTML entity
            Assert.Contains("Send Log", html);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task LogsEndpoint_WithoutOriginHeader_OnLoopback_ShouldReturnLogs()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            // Normal browser same-origin GET request does not include Origin header
            HttpResponseMessage response = await httpClient.GetAsync($"http://localhost:{server.Port}/api/logs");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            string json = await response.Content.ReadAsStringAsync();
            Assert.Contains("logs", json);
            Assert.Contains("totalLines", json);
            Assert.Contains("fetchedAt", json);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task ClearLogsEndpoint_UntrustedOrigin_ShouldReturnForbidden()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://localhost:{server.Port}/api/logs/clear");
            request.Headers.Add("Origin", $"http://localhost:{server.Port}.evil.com");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task ClearLogsEndpoint_TrustedOrigin_ShouldReturnOk()
    {
        MockHttpMessageHandler handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        TestHttpClientFactory factory = new TestHttpClientFactory(handler);

        LocalUiServer server = new LocalUiServer(_logger, _keyManager, factory, _machineId, "https://hub.example.test/", port: 0);

        try
        {
            await server.StartAsync();

            using HttpClient httpClient = new HttpClient();
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, $"http://localhost:{server.Port}/api/logs/clear");
            request.Headers.Add("Origin", $"http://localhost:{server.Port}");

            HttpResponseMessage response = await httpClient.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            string body = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);
            Assert.True(doc.RootElement.GetProperty("success").GetBoolean());
            Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("clearedAt").GetString()));
        }
        finally
        {
            await server.StopAsync();
        }
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

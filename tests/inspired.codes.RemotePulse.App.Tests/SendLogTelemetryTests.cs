using System.Net;
using System.Net.Http;
using System.Text.Json;
using InspiredCodes.RemotePulse.App.Services;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

public class SendLogTelemetryTests
{
    [Fact]
    public async Task PostTelemetryAsync_WhenOnline_SendsSignedPayloadAndReturnsTrue()
    {
        HttpRequestMessage? capturedRequest = null;
        string? capturedBody = null;

        var handler = new MockHttpMessageHandler(async req =>
        {
            capturedRequest = req;
            if (req.Content != null)
            {
                capturedBody = await req.Content.ReadAsStringAsync();
            }
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        var js = new FakeJSRuntime();
        var storage = new LocalStorageService(js);
        var crypto = new CryptoService(js);
        var appState = new AppState(storage, crypto)
        {
            AppId = "test-app-id-12345",
            DeviceOnline = true,
            HubReachable = true
        };

        var httpClient = new HttpClient(handler);
        var client = new HubApiClient(httpClient, appState, crypto);

        var entry = new TelemetryLogEntry
        {
            Source = "App",
            MachineId = "test-machine-id",
            AppId = appState.AppId,
            LogLevel = "Information",
            Category = "Diagnostics",
            EventName = "ManualAppLogUpload",
            Message = "Manual log upload test",
            DataJson = "{\"ConsoleOutput\":\"line1\\nline2\"}"
        };

        bool result = await client.PostTelemetryAsync("https://rmpls.inspired.codes", entry);

        Assert.True(result);
        Assert.Equal(1, handler.RequestCount);
        Assert.NotNull(capturedRequest);
        Assert.Equal("/api/telemetry/logs", capturedRequest.RequestUri?.AbsolutePath);
        Assert.True(capturedRequest.Headers.Contains("X-App-Id"));
        Assert.True(capturedRequest.Headers.Contains("X-Timestamp"));
        Assert.True(capturedRequest.Headers.Contains("X-Nonce"));
        Assert.True(capturedRequest.Headers.Contains("X-Signature"));
        Assert.NotNull(capturedBody);
        Assert.Contains("ManualAppLogUpload", capturedBody);
        Assert.Contains("ConsoleOutput", capturedBody);
    }

    [Fact]
    public async Task PostTelemetryAsync_WhenDeviceOffline_ReturnsFalseWithoutCallingNetwork()
    {
        var handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var js = new FakeJSRuntime();
        var storage = new LocalStorageService(js);
        var crypto = new CryptoService(js);
        var appState = new AppState(storage, crypto)
        {
            AppId = "test-app-id-12345",
            DeviceOnline = false,
            HubReachable = true
        };

        var httpClient = new HttpClient(handler);
        var client = new HubApiClient(httpClient, appState, crypto);

        var entry = new TelemetryLogEntry
        {
            Source = "App",
            EventName = "ManualAppLogUpload"
        };

        bool result = await client.PostTelemetryAsync("https://rmpls.inspired.codes", entry);

        Assert.False(result);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task PostTelemetryAsync_WhenHubReachableFalse_ReturnsFalseWithoutCallingNetwork()
    {
        var handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var js = new FakeJSRuntime();
        var storage = new LocalStorageService(js);
        var crypto = new CryptoService(js);
        var appState = new AppState(storage, crypto)
        {
            AppId = "test-app-id-12345",
            DeviceOnline = true,
            HubReachable = false
        };

        var httpClient = new HttpClient(handler);
        var client = new HubApiClient(httpClient, appState, crypto);

        var entry = new TelemetryLogEntry
        {
            Source = "App",
            EventName = "ManualAppLogUpload"
        };

        bool result = await client.PostTelemetryAsync("https://rmpls.inspired.codes", entry);

        Assert.False(result);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task PostTelemetryAsync_WhenServerReturns500_ReturnsFalse()
    {
        var handler = new MockHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)));
        var js = new FakeJSRuntime();
        var storage = new LocalStorageService(js);
        var crypto = new CryptoService(js);
        var appState = new AppState(storage, crypto)
        {
            AppId = "test-app-id-12345",
            DeviceOnline = true,
            HubReachable = true
        };

        var httpClient = new HttpClient(handler);
        var client = new HubApiClient(httpClient, appState, crypto);

        var entry = new TelemetryLogEntry
        {
            Source = "App",
            EventName = "ManualAppLogUpload"
        };

        bool result = await client.PostTelemetryAsync("https://rmpls.inspired.codes", entry);

        Assert.False(result);
        Assert.Equal(1, handler.RequestCount);
    }
}

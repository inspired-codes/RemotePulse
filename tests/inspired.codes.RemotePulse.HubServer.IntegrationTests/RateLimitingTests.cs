using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.HubServer.IntegrationTests;

/// <summary>
/// The Hub's own rate limits (both hosts run Caddy, and stock Caddy has none): a token bucket on
/// every /api/* request and a tighter one on the unauthenticated /api/support/report, both per client IP.
/// TestServer connections have no peer address, and those are never limited, so each test sets
/// X-Forwarded-For the way Caddy does live. UseForwardedHeaders turns that into the
/// RemoteIpAddress the limiter partitions on. Each test gets its own factory, and with it its
/// own limiter state and InMemory database.
/// </summary>
public class RateLimitingTests
{
    private static WebApplicationFactory<Program> CreateFactory(string dbName, Dictionary<string, string?> limits)
    {
        limits["ConnectionStrings:DefaultConnection"] = $"InMemory_{dbName}";
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(limits));
        });
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> factory, string clientIp)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Forwarded-For", clientIp);
        return client;
    }

    // Refill at the minimum, 1 token per second: the few requests per test take milliseconds,
    // well inside one replenishment period, so the bucket is still empty when a test expects 429.
    private static Dictionary<string, string?> ApiLimit(int burst) => new()
    {
        { "RateLimiting:ApiBurst", burst.ToString() },
        { "RateLimiting:ApiPermitsPerSecond", "1" }
    };

    [Fact]
    public async Task Api_BurstExhausted_Returns429WithRetryAfter()
    {
        using var factory = CreateFactory(nameof(Api_BurstExhausted_Returns429WithRetryAfter), ApiLimit(burst: 3));
        using var client = CreateClient(factory, "203.0.113.10");

        for (int i = 0; i < 3; i++)
        {
            using var ok = await client.GetAsync("/api/pairing/status/health");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        using var limited = await client.GetAsync("/api/pairing/status/health");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
    }

    [Fact]
    public async Task Api_LimitIsPerClientIp()
    {
        using var factory = CreateFactory(nameof(Api_LimitIsPerClientIp), ApiLimit(burst: 2));
        using var first = CreateClient(factory, "203.0.113.20");
        using var second = CreateClient(factory, "203.0.113.21");

        for (int i = 0; i < 2; i++)
        {
            using var ok = await first.GetAsync("/api/pairing/status/health");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var limited = await first.GetAsync("/api/pairing/status/health");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        using var otherIp = await second.GetAsync("/api/pairing/status/health");
        Assert.Equal(HttpStatusCode.OK, otherIp.StatusCode);
    }

    [Fact]
    public async Task NonApiPaths_AreNotLimited()
    {
        using var factory = CreateFactory(nameof(NonApiPaths_AreNotLimited), ApiLimit(burst: 1));
        using var client = CreateClient(factory, "203.0.113.30");

        using var ok = await client.GetAsync("/api/pairing/status/health");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        using var limited = await client.GetAsync("/api/pairing/status/health");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        for (int i = 0; i < 3; i++)
        {
            using var root = await client.GetAsync("/");
            Assert.NotEqual(HttpStatusCode.TooManyRequests, root.StatusCode);
        }
    }

    [Fact]
    public async Task NoPeerAddress_IsNeverLimited()
    {
        // Pins the in-process exemption the rest of the test suite relies on. Live, Kestrel
        // always sets a peer address, so no real request takes this path.
        using var factory = CreateFactory(nameof(NoPeerAddress_IsNeverLimited), ApiLimit(burst: 1));
        using var client = factory.CreateClient();

        for (int i = 0; i < 5; i++)
        {
            using var response = await client.GetAsync("/api/pairing/status/health");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task SupportReport_FourthReportFromSameIp_Returns429()
    {
        using var factory = CreateFactory(nameof(SupportReport_FourthReportFromSameIp_Returns429), new()
        {
            { "RateLimiting:SupportReportBurst", "3" },
            { "RateLimiting:SupportReportsPerMinute", "1" }
        });
        using var client = CreateClient(factory, "203.0.113.40");
        var report = new SupportReportRequest { Source = "Installer", Message = "sc.exe create failed, exit code 2" };

        for (int i = 0; i < 3; i++)
        {
            using var ok = await client.PostAsJsonAsync("/api/support/report", report);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        using var limited = await client.PostAsJsonAsync("/api/support/report", report);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        // The general /api/* bucket (default burst 20) is separate and still has room.
        using var health = await client.GetAsync("/api/pairing/status/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }
}

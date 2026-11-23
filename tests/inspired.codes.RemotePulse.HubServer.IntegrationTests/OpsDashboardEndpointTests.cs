using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using InspiredCodes.RemotePulse.HubServer.Dashboard;
using InspiredCodes.RemotePulse.HubServer.Data;
using Xunit;

namespace InspiredCodes.RemotePulse.HubServer.IntegrationTests;

public class OpsDashboardEndpointTests
{
    [Fact]
    public async Task OpsEndpoints_WithoutConfiguredToken_ShouldReturnUnauthorized()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", "InMemory_NoToken" }
                });
            });
        });

        var client = factory.CreateClient();

        var resHtml = await client.GetAsync("/ops");
        Assert.Equal(HttpStatusCode.Unauthorized, resHtml.StatusCode);

        var resMetrics = await client.GetAsync("/ops/metrics");
        Assert.Equal(HttpStatusCode.Unauthorized, resMetrics.StatusCode);
    }

    [Fact]
    public async Task OpsEndpoints_WithTokenConfigured_ShouldEnforceAuthentication()
    {
        const string secretToken = "test_ops_secret_token_12345";

        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", "InMemory_TokenAuth" },
                    { "ADMIN_TOKEN", secretToken }
                });
            });
        });

        var client = factory.CreateClient();

        // 1. Unauthenticated request -> 401
        var unauthRes = await client.GetAsync("/ops/metrics");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthRes.StatusCode);

        // 2. Wrong token -> 401
        var wrongReq = new HttpRequestMessage(HttpMethod.Get, "/ops/metrics");
        wrongReq.Headers.Add("X-Admin-Token", "wrong_token");
        var wrongRes = await client.SendAsync(wrongReq);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongRes.StatusCode);

        // 3. Valid X-Admin-Token header -> 200
        var validHeaderReq = new HttpRequestMessage(HttpMethod.Get, "/ops/metrics");
        validHeaderReq.Headers.Add("X-Admin-Token", secretToken);
        var validHeaderRes = await client.SendAsync(validHeaderReq);
        Assert.Equal(HttpStatusCode.OK, validHeaderRes.StatusCode);

        // 4. Valid ?token= query param -> 200
        var validQueryRes = await client.GetAsync($"/ops/metrics?token={secretToken}");
        Assert.Equal(HttpStatusCode.OK, validQueryRes.StatusCode);

        // 5. Valid ?token= on HTML dashboard -> 200 HTML
        var validHtmlRes = await client.GetAsync($"/ops?token={secretToken}");
        Assert.Equal(HttpStatusCode.OK, validHtmlRes.StatusCode);
        var html = await validHtmlRes.Content.ReadAsStringAsync();
        Assert.Contains("RemotePulse Ops", html);
    }

    [Fact]
    public async Task OpsMetrics_ShouldReturnAccurateClientHealthAndThroughput()
    {
        const string secretToken = "metrics_token_xyz";
        string dbName = $"InMemory_Metrics_{Guid.NewGuid():N}";

        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", dbName },
                    { "ADMIN_TOKEN", secretToken }
                });
            });
        });

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
            var now = DateTime.UtcNow;

            // Seed clients: 1 Online, 1 Degraded/Offline
            db.Clients.Add(new Client
            {
                MachineId = "worker-online",
                PublicKey = "key1",
                LastSeenUtc = now.AddSeconds(-2),
                PollIntervalSeconds = 10
            });
            db.Clients.Add(new Client
            {
                MachineId = "worker-offline",
                PublicKey = "key2",
                LastSeenUtc = now.AddHours(-2),
                PollIntervalSeconds = 10
            });

            // Seed commands: 2 successful, 1 failed
            db.CommandResults.Add(new CommandResultEntity
            {
                CommandId = "cmd-1",
                MachineId = "worker-online",
                Success = true,
                DurationMs = 120.5,
                IsEncrypted = true,
                EncryptedPayload = "BLOB1",
                DateCreated = now.AddMinutes(-5)
            });
            db.CommandResults.Add(new CommandResultEntity
            {
                CommandId = "cmd-2",
                MachineId = "worker-online",
                Success = true,
                DurationMs = 80.0,
                IsEncrypted = true,
                EncryptedPayload = "BLOB2",
                DateCreated = now.AddHours(-2)
            });
            db.CommandResults.Add(new CommandResultEntity
            {
                CommandId = "cmd-3",
                MachineId = "worker-offline",
                Success = false,
                DurationMs = 250.0,
                IsEncrypted = true,
                EncryptedPayload = "BLOB3",
                DateCreated = now.AddHours(-10)
            });

            // Seed log
            db.SystemLogs.Add(new SystemLogEntity
            {
                Timestamp = now.AddMinutes(-1),
                LogLevel = "Information",
                Source = "Worker",
                MachineId = "worker-online",
                Category = "Worker",
                EventName = "Heartbeat",
                Message = "Worker running normal"
            });

            await db.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        var response = await client.GetAsync($"/ops/metrics?token={secretToken}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var data = await response.Content.ReadFromJsonAsync<OpsDashboardData>();
        Assert.NotNull(data);

        // Verify clients
        Assert.Equal(2, data.Clients.Count);
        var onlineWorker = data.Clients.Find(c => c.MachineId == "worker-online");
        Assert.NotNull(onlineWorker);
        Assert.Equal("Online", onlineWorker.Health);

        var offlineWorker = data.Clients.Find(c => c.MachineId == "worker-offline");
        Assert.NotNull(offlineWorker);
        Assert.Equal("Offline", offlineWorker.Health);

        // Verify throughput
        Assert.Equal(3, data.Throughput.TotalCommands);
        Assert.Equal(1, data.Throughput.Last1Hour);
        Assert.Equal(3, data.Throughput.Last24Hours);
        Assert.Equal(2, data.Throughput.Successful);
        Assert.Equal(1, data.Throughput.Failed);

        // Verify recent command results
        Assert.Equal(3, data.RecentCommands.Count);
        Assert.All(data.RecentCommands, c => Assert.Equal("[Encrypted Output]", c.OutputSnippet));

        // Verify logs
        Assert.Single(data.RecentLogs);
        Assert.Equal("Worker running normal", data.RecentLogs[0].Message);
    }
}

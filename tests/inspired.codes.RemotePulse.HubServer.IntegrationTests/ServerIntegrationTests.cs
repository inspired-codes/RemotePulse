using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using InspiredCodes.RemotePulse.HubServer.Data;
using Xunit;

namespace InspiredCodes.RemotePulse.HubServer.IntegrationTests;

public class ServerIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _httpClient;

    public ServerIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", "InMemory_ServerIntegrationTests" }
                });
            });
        });
        _httpClient = _factory.CreateClient();
    }

    [Fact]
    public async Task Health_ShouldReportTheHubBuildVersion()
    {
        // "What is live" checks compare against this, so it must follow the HubServer .csproj
        // <Version> - it used to be a hard-coded "1.5.0" whatever was actually deployed.
        // AssemblyVersion is a second, independent stamp of the same <Version>.
        Version assemblyVersion = typeof(Program).Assembly.GetName().Version!;
        string expected = $"{assemblyVersion.Major}.{assemblyVersion.Minor}.{assemblyVersion.Build}";

        var health = await _httpClient.GetFromJsonAsync<JsonElement>("/api/pairing/status/health");

        Assert.Equal("ok", health.GetProperty("status").GetString());
        Assert.Equal(expected, health.GetProperty("version").GetString());
    }

    [Fact]
    public async Task RetiredLegacyEndpoints_AdminTokensCreate_And_ClientsRegister_ShouldReturnNotFound()
    {
        var createResponse = await _httpClient.PostAsync("/api/admin/tokens/create", null);
        Assert.Equal(HttpStatusCode.NotFound, createResponse.StatusCode);

        var regResponse = await _httpClient.PostAsync("/api/clients/register", null);
        Assert.Equal(HttpStatusCode.NotFound, regResponse.StatusCode);
    }

    [Fact]
    public async Task PruneExpiredDataService_ShouldPruneExpiredRecordsOnly()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<PruneExpiredDataService>>();
        var scopeFactory = scope.ServiceProvider.GetRequiredService<IServiceScopeFactory>();
        var pruner = new PruneExpiredDataService(scopeFactory, logger);

        var now = DateTime.UtcNow;
        string expiredNonce = $"exp-nonce-{Guid.NewGuid():N}";
        string activeNonce = $"act-nonce-{Guid.NewGuid():N}";
        string expiredSecret = $"sec-exp-{Guid.NewGuid():N}";
        string activeSecret = $"sec-act-{Guid.NewGuid():N}";
        string expiredCmdId = $"cmd-exp-{Guid.NewGuid():N}";
        string activeCmdId = $"cmd-act-{Guid.NewGuid():N}";
        string oldMsg = $"old-log-{Guid.NewGuid():N}";
        string newMsg = $"new-log-{Guid.NewGuid():N}";

        db.SeenNonces.Add(new SeenNonce { NonceKey = expiredNonce, Expiry = now.AddMinutes(-10) });
        db.SeenNonces.Add(new SeenNonce { NonceKey = activeNonce, Expiry = now.AddMinutes(10) });

        db.PendingCoPresences.Add(new PendingCoPresence { PairingId = expiredSecret, ExpiresAtUtc = now.AddMinutes(-5) });
        db.PendingCoPresences.Add(new PendingCoPresence { PairingId = activeSecret, ExpiresAtUtc = now.AddMinutes(5) });

        db.CommandResults.Add(new CommandResultEntity { CommandId = expiredCmdId, MachineId = "m1", DateCreated = now.AddDays(-10) });
        db.CommandResults.Add(new CommandResultEntity { CommandId = activeCmdId, MachineId = "m2", DateCreated = now.AddDays(-1) });

        db.SystemLogs.Add(new SystemLogEntity { Timestamp = now.AddDays(-5), LogLevel = "Information", Message = oldMsg });
        db.SystemLogs.Add(new SystemLogEntity { Timestamp = now.AddHours(-1), LogLevel = "Information", Message = newMsg });

        await db.SaveChangesAsync();

        await pruner.PruneAsync();

        var remainingNonces = await db.SeenNonces.Select(n => n.NonceKey).ToListAsync();
        Assert.DoesNotContain(expiredNonce, remainingNonces);
        Assert.Contains(activeNonce, remainingNonces);

        var remainingCoPresences = await db.PendingCoPresences.Select(p => p.PairingId).ToListAsync();
        Assert.DoesNotContain(expiredSecret, remainingCoPresences);
        Assert.Contains(activeSecret, remainingCoPresences);

        var remainingResults = await db.CommandResults.Select(r => r.CommandId).ToListAsync();
        Assert.DoesNotContain(expiredCmdId, remainingResults);
        Assert.Contains(activeCmdId, remainingResults);

        var remainingLogs = await db.SystemLogs.Select(l => l.Message).ToListAsync();
        Assert.DoesNotContain(oldMsg, remainingLogs);
        Assert.Contains(newMsg, remainingLogs);
    }
}

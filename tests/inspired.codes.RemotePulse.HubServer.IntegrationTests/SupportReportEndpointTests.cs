using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using InspiredCodes.RemotePulse.HubServer.Data;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.HubServer.IntegrationTests;

/// <summary>
/// /api/support/report is deliberately unauthenticated (a failing install has no signed
/// identity to authenticate with yet), so these tests focus on what actually guards it:
/// input validation, size/length caps, and that it lands where /ops expects to find it.
/// Each test gets its own WebApplicationFactory + uniquely-named InMemory database (matching
/// OpsDashboardEndpointTests's pattern, not TelemetryEndpointTests's shared-fixture one) -
/// EF Core's InMemory provider keys its store by database name at the process level, so a
/// shared IClassFixture (or even fresh factories reusing the same name) lets one test's rows
/// leak into another's assertions.
/// </summary>
public class SupportReportEndpointTests
{
    private static WebApplicationFactory<Program> CreateFactory(string dbName)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    { "ConnectionStrings:DefaultConnection", $"InMemory_{dbName}" }
                });
            });
        });
    }

    [Fact]
    public async Task Report_NoAuthHeadersAtAll_ShouldStillSucceed()
    {
        // The whole point: no X-Client-Id, no X-Signature, nothing - this must work anyway.
        using var factory = CreateFactory(nameof(Report_NoAuthHeadersAtAll_ShouldStillSucceed));
        var client = factory.CreateClient();

        var report = new SupportReportRequest { Source = "Installer", Message = "sc.exe create failed, exit code 2" };
        var response = await client.PostAsJsonAsync("/api/support/report", report);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Report_EmptyMessage_ShouldReturnBadRequest()
    {
        using var factory = CreateFactory(nameof(Report_EmptyMessage_ShouldReturnBadRequest));
        var client = factory.CreateClient();

        var report = new SupportReportRequest { Source = "Web", Message = "   " };
        var response = await client.PostAsJsonAsync("/api/support/report", report);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Report_UnknownSource_IsNormalizedNotRejected()
    {
        // A field an attacker or a future caller could get wrong shouldn't 400 - just don't
        // trust it for the LogLevel decision either.
        using var factory = CreateFactory(nameof(Report_UnknownSource_IsNormalizedNotRejected));
        var client = factory.CreateClient();

        var report = new SupportReportRequest { Source = "SomethingElse", Message = "hello" };
        var response = await client.PostAsJsonAsync("/api/support/report", report);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        var row = Assert.Single(db.SystemLogs);
        Assert.Equal("SupportReport:Unknown", row.Source);
    }

    [Fact]
    public async Task Report_Installer_IsStoredAsErrorLevel_Web_AsInformation()
    {
        using var factory = CreateFactory(nameof(Report_Installer_IsStoredAsErrorLevel_Web_AsInformation));
        var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/support/report", new SupportReportRequest { Source = "Installer", Message = "install failed" });
        await client.PostAsJsonAsync("/api/support/report", new SupportReportRequest { Source = "Web", Message = "user report" });

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        Assert.Equal(2, db.SystemLogs.Count());
        Assert.Equal("Error", db.SystemLogs.Single(l => l.Source == "SupportReport:Installer").LogLevel);
        Assert.Equal("Information", db.SystemLogs.Single(l => l.Source == "SupportReport:Web").LogLevel);
    }

    [Fact]
    public async Task Report_OverlongMessage_IsTruncatedNotRejected()
    {
        using var factory = CreateFactory(nameof(Report_OverlongMessage_IsTruncatedNotRejected));
        var client = factory.CreateClient();

        var report = new SupportReportRequest { Source = "Web", Message = new string('x', 5000) };
        var response = await client.PostAsJsonAsync("/api/support/report", report);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        Assert.True(db.SystemLogs.Single().Message.Length <= 500);
    }

    [Fact]
    public async Task Report_MalformedDetailsJson_IsWrappedSafelyNotRejected()
    {
        using var factory = CreateFactory(nameof(Report_MalformedDetailsJson_IsWrappedSafelyNotRejected));
        var client = factory.CreateClient();

        var report = new SupportReportRequest
        {
            Source = "Installer",
            Message = "boom",
            DetailsJson = "{not valid json"
        };
        var response = await client.PostAsJsonAsync("/api/support/report", report);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        string? dataJson = db.SystemLogs.Single().DataJson;
        Assert.NotNull(dataJson);
        // Must still be valid, storable JSON even though the caller's input wasn't.
        using var doc = JsonDocument.Parse(dataJson!);
    }

    [Fact]
    public async Task Report_ValidDetailsJson_IsPreservedStructured()
    {
        using var factory = CreateFactory(nameof(Report_ValidDetailsJson_IsPreservedStructured));
        var client = factory.CreateClient();

        var report = new SupportReportRequest
        {
            Source = "Installer",
            Message = "boom",
            DetailsJson = """{"os":"Windows 11","failedStep":"Install service"}"""
        };
        await client.PostAsJsonAsync("/api/support/report", report);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        using var doc = JsonDocument.Parse(db.SystemLogs.Single().DataJson!);
        var details = doc.RootElement.GetProperty("details");
        Assert.Equal("Windows 11", details.GetProperty("os").GetString());
        Assert.Equal("Install service", details.GetProperty("failedStep").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Report_DoesNotStoreTheCallersIp(bool oversizedDetails)
    {
        // Covers both DataJson shapes: the normal one and the "truncated" fallback past 8 KB.
        using var factory = CreateFactory($"{nameof(Report_DoesNotStoreTheCallersIp)}_{oversizedDetails}");
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Forwarded-For", "203.0.113.7");

        string details = oversizedDetails
            ? JsonSerializer.Serialize(new { blob = new string('x', 9000) })
            : """{"os":"Windows 11"}""";
        var report = new SupportReportRequest { Source = "Installer", Message = "boom", DetailsJson = details };
        await client.PostAsJsonAsync("/api/support/report", report);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        string dataJson = db.SystemLogs.Single().DataJson!;
        using var doc = JsonDocument.Parse(dataJson);
        Assert.False(doc.RootElement.TryGetProperty("clientIp", out _));
        Assert.DoesNotContain("203.0.113.7", dataJson);
        Assert.Equal(oversizedDetails, doc.RootElement.TryGetProperty("truncated", out _));
    }

    [Fact]
    public async Task Report_InstallerSuccess_WithExplicitInformationLevel_OverridesTheErrorDefault()
    {
        // Regression test: a "good news" confirmation from the Installer source used to always
        // land as LogLevel "Error" because the Hub inferred severity from Source alone - this is
        // exactly the case that needed a caller-supplied override.
        using var factory = CreateFactory(nameof(Report_InstallerSuccess_WithExplicitInformationLevel_OverridesTheErrorDefault));
        var client = factory.CreateClient();

        var report = new SupportReportRequest { Source = "Installer", Message = "install succeeded", LogLevel = "Information" };
        await client.PostAsJsonAsync("/api/support/report", report);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        Assert.Equal("Information", db.SystemLogs.Single().LogLevel);
    }

    [Fact]
    public async Task Report_InvalidLogLevel_FallsBackToSourceDefault()
    {
        using var factory = CreateFactory(nameof(Report_InvalidLogLevel_FallsBackToSourceDefault));
        var client = factory.CreateClient();

        var report = new SupportReportRequest { Source = "Installer", Message = "boom", LogLevel = "Critical" };
        await client.PostAsJsonAsync("/api/support/report", report);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        // "Critical" isn't in the allow-list, so it must not pass through verbatim.
        Assert.Equal("Error", db.SystemLogs.Single().LogLevel);
    }

    [Fact]
    public async Task Report_WithMachineId_IsStoredOnTheRow()
    {
        using var factory = CreateFactory(nameof(Report_WithMachineId_IsStoredOnTheRow));
        var client = factory.CreateClient();

        var machineId = Guid.NewGuid().ToString();
        var report = new SupportReportRequest { Source = "Installer", Message = "boom", MachineId = machineId };
        await client.PostAsJsonAsync("/api/support/report", report);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        Assert.Equal(machineId, db.SystemLogs.Single().MachineId);
    }
}

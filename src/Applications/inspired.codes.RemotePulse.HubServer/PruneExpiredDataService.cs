using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using InspiredCodes.RemotePulse.HubServer.Data;

namespace InspiredCodes.RemotePulse.HubServer;

/// <summary>
/// Background service that periodically removes expired nonces, stale pairing tickets,
/// old command results, and telemetry logs.
/// </summary>
public sealed class PruneExpiredDataService(
    IServiceScopeFactory scopeFactory,
    ILogger<PruneExpiredDataService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using PeriodicTimer timer = new(Interval);
        while (!stoppingToken.IsCancellationRequested && await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await PruneAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error occurred during data pruning.");
            }
        }
    }

    public async Task PruneAsync(CancellationToken cancellationToken = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<RemotePulseContext>();
        var now = DateTime.UtcNow;

        if (db.Database.IsRelational())
        {
            await db.SeenNonces.Where(n => n.Expiry <= now).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            await db.PendingCoPresences.Where(p => p.ExpiresAtUtc <= now).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            await db.CommandResults.Where(r => r.DateCreated <= now.AddDays(-7)).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            await db.SystemLogs.Where(l => l.Timestamp <= now.AddDays(-3)).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var expiredNonces = await db.SeenNonces.Where(n => n.Expiry <= now).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (expiredNonces.Count > 0) db.SeenNonces.RemoveRange(expiredNonces);

            var expiredCoPresences = await db.PendingCoPresences.Where(p => p.ExpiresAtUtc <= now).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (expiredCoPresences.Count > 0) db.PendingCoPresences.RemoveRange(expiredCoPresences);

            var staleResults = await db.CommandResults.Where(r => r.DateCreated <= now.AddDays(-7)).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (staleResults.Count > 0) db.CommandResults.RemoveRange(staleResults);

            var expiredLogs = await db.SystemLogs.Where(l => l.Timestamp <= now.AddDays(-3)).ToListAsync(cancellationToken).ConfigureAwait(false);
            if (expiredLogs.Count > 0) db.SystemLogs.RemoveRange(expiredLogs);

            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.RemotePulse.HubServer.Data;

public class RemotePulseContext : DbContext
{
    public DbSet<Client> Clients { get; set; } = null!;
    public DbSet<Pairing> Pairings { get; set; } = null!;
    public DbSet<ServerCommandEntity> CommandQueue { get; set; } = null!;
    public DbSet<CommandResultEntity> CommandResults { get; set; } = null!;
    public DbSet<SeenNonce> SeenNonces { get; set; } = null!;
    public DbSet<SystemLogEntity> SystemLogs { get; set; } = null!;

    /// <summary>
    /// Co-presence pairing tickets (see docs/specs/pairing-v2-key-binding-spec.md). A row is
    /// created when a Worker pushes an HKDF-derived <see cref="PendingCoPresence.PairingId"/>,
    /// filled in further when a Mobile App submits the matching <c>PairingId</c> and
    /// <see cref="PendingCoPresence.AppBindTag"/>, and deleted once both sides are present and
    /// the match has been finalized (either into a new Client + Pairing, or rejected).
    /// </summary>
    public DbSet<PendingCoPresence> PendingCoPresences { get; set; } = null!;

    public RemotePulseContext(DbContextOptions<RemotePulseContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Client>(entity =>
        {
            entity.HasKey(c => c.MachineId);
            entity.Property(c => c.WorkerVersion).HasMaxLength(WorkerReportedInfo.MaxVersionLength);
            entity.Property(c => c.WorkerCapabilities).HasMaxLength(WorkerReportedInfo.MaxCapabilitiesLength);
        });
        modelBuilder.Entity<Pairing>().HasKey(p => new { p.MachineId, p.AppId });
        modelBuilder.Entity<ServerCommandEntity>(entity =>
        {
            entity.HasKey(c => c.CommandId);
            entity.HasIndex(c => new { c.MachineId, c.DateCreated });
        });
        modelBuilder.Entity<CommandResultEntity>(entity =>
        {
            entity.HasKey(r => r.CommandId);
            entity.HasIndex(r => r.DateCreated);
        });
        modelBuilder.Entity<SeenNonce>(entity =>
        {
            entity.HasKey(n => n.NonceKey);
            entity.HasIndex(n => n.Expiry);
        });
        modelBuilder.Entity<PendingCoPresence>().HasKey(p => p.PairingId);
        modelBuilder.Entity<SystemLogEntity>(entity =>
        {
            entity.HasKey(l => l.Id);
            entity.Property(l => l.DataJson).HasColumnType("jsonb");
            entity.HasIndex(l => l.Timestamp);
            entity.HasIndex(l => new { l.Source, l.LogLevel });
        });
    }
}

public class PendingCoPresence
{
    /// <summary>
    /// PairingId = HKDF-derived match key, never the secret.
    /// </summary>
    public string PairingId { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }

    public string? ClientMachineId { get; set; }
    public string? ClientPublicKey { get; set; }

    public string? AppId { get; set; }
    public string? AppPublicKey { get; set; }
    public string? AppBindTag { get; set; }
}

public class Client
{
    public string MachineId { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public DateTime DateCreated { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Last time this Worker made a successfully-authenticated request (poll, result post, or
    /// pairing confirm). This is the liveness heartbeat the App's watchdog reads - it's stamped
    /// only after a signature is verified, so it can't be forged by an unauthenticated caller.
    /// Null means the machine has registered but never checked in.
    /// </summary>
    public DateTime? LastSeenUtc { get; set; }

    /// <summary>
    /// The Worker's own configured poll interval, self-reported via the X-Poll-Interval header.
    /// Lets the Hub scale the "is it online?" threshold to each machine instead of assuming the
    /// 30s default - a Worker deliberately configured to poll slowly would otherwise always look
    /// offline. Null until the machine reports one.
    /// </summary>
    public int? PollIntervalSeconds { get; set; }

    /// <summary>
    /// The Worker's own version, self-reported via the X-Worker-Version header (Worker 1.2.0+).
    /// Null for older Workers, which don't send it.
    /// </summary>
    public string? WorkerVersion { get; set; }

    /// <summary>
    /// Comma-separated feature tokens the Worker self-reports via X-Worker-Capabilities
    /// (e.g. "envelope-v2,params"). The App uses them only to decide which features to offer:
    /// the header isn't covered by the request signature, so safety must never depend on it -
    /// a Worker that gets a command it can't handle rejects it (fail-closed).
    /// </summary>
    public string? WorkerCapabilities { get; set; }
}

public class Pairing
{
    public string MachineId { get; set; } = string.Empty;
    public string AppId { get; set; } = string.Empty;
    public string AppPublicKey { get; set; } = string.Empty;
    public bool IsLocked { get; set; }

    /// <summary>
    /// Set once the Windows Client has picked up this pairing's AppId/AppPublicKey via its
    /// own poll loop (see the co-presence flow in docs/communication.md). Null means the Client
    /// doesn't know about this pairing yet and hasn't saved it to its local pairing.json.
    /// </summary>
    public DateTime? AnnouncedToClientAtUtc { get; set; }

    /// <summary>
    /// PairingId = HKDF-derived match key, never the secret. Sent in PAIRING-ANNOUNCE
    /// alongside <see cref="AppBindTag"/> so the Worker can look up the active secret S
    /// in its local ring and verify the key-binding tag.
    /// </summary>
    public string? PairingId { get; set; }

    /// <summary>
    /// HMAC-SHA256 key-binding tag computed by the App with <c>bindKey</c> derived from S,
    /// binding <c>pid</c>, the Worker's fingerprint <c>fp</c>, <see cref="AppId"/>, and
    /// <see cref="AppPublicKey"/>. Relayed opaquely to the Worker in PAIRING-ANNOUNCE.
    /// </summary>
    public string? AppBindTag { get; set; }
}

public class ServerCommandEntity
{
    public string CommandId { get; set; } = string.Empty;
    public string MachineId { get; set; } = string.Empty;
    public string Script { get; set; } = string.Empty;
    public ExecutionMode ExecutionMode { get; set; }
    public bool IsHandshake { get; set; }
    public int? TimeoutSeconds { get; set; }
    public DateTime DateCreated { get; set; } = DateTime.UtcNow;
}

public class CommandResultEntity
{
    public string CommandId { get; set; } = string.Empty;
    public string MachineId { get; set; } = string.Empty;
    public string? AppId { get; set; }
    public DateTime DateCreated { get; set; } = DateTime.UtcNow;

    // Unauthenticated envelope metrics (for Hub /ops dashboard only)
    public bool Success { get; set; }
    public double DurationMs { get; set; }

    // Encryption payload (E2EE)
    public bool IsEncrypted { get; set; } = true;
    public string? EncryptedPayload { get; set; }

    // Rejections only (when Worker rejects invalid envelope before execution)
    public string? RejectionReason { get; set; }
}

public class SeenNonce
{
    public string NonceKey { get; set; } = string.Empty;
    public DateTime Expiry { get; set; }
}

public class SystemLogEntity
{
    public long Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Source { get; set; } = string.Empty;
    public string? MachineId { get; set; }
    public string? AppId { get; set; }
    public string LogLevel { get; set; } = "Information";
    public string Category { get; set; } = string.Empty;
    public string EventName { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string? DataJson { get; set; }
}


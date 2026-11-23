using System;

namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// A structured, privacy-safe diagnostic event emitted by Worker, Mobile App, or Hub.
/// Excludes raw secrets and script texts; captures protocol states, timing, errors, and metadata.
/// </summary>
public class TelemetryLogEntry
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Component generating the log entry: "Worker", "App", or "Hub".
    /// </summary>
    public string Source { get; set; } = string.Empty;

    public string? MachineId { get; set; }

    public string? AppId { get; set; }

    /// <summary>
    /// Log severity level: "Information", "Warning", or "Error".
    /// </summary>
    public string LogLevel { get; set; } = "Information";

    /// <summary>
    /// Functional subsystem: e.g. "PollingWorker", "CryptoService", "Watchdog", "PowerShellEngine".
    /// </summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>
    /// Machine-readable event name: e.g. "SignatureVerificationFailed", "CommandExecuted", "PollTimeout".
    /// </summary>
    public string EventName { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable message describing the event.
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Structured diagnostic parameters serialized as JSON (stored as jsonb in PostgreSQL).
    /// </summary>
    public string? DataJson { get; set; }
}

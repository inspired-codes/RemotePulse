using System;
using System.Collections.Generic;

namespace InspiredCodes.RemotePulse.HubServer.Dashboard;

public class OpsDashboardData
{
    public DateTime ServerTimeUtc { get; set; }
    public string Environment { get; set; } = string.Empty;
    public List<OpsClientInfo> Clients { get; set; } = new();
    public OpsThroughputInfo Throughput { get; set; } = new();
    public List<OpsCommandResult> RecentCommands { get; set; } = new();
    public List<OpsSystemLog> RecentLogs { get; set; } = new();
}

public class OpsClientInfo
{
    public string MachineId { get; set; } = string.Empty;
    public string Health { get; set; } = "Offline";
    public int? MissedPolls { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public double? AgeSeconds { get; set; }
    public int PollIntervalSeconds { get; set; }
    public List<string> PairedApps { get; set; } = new();
}

public class OpsThroughputInfo
{
    public int TotalCommands { get; set; }
    public int Last1Hour { get; set; }
    public int Last24Hours { get; set; }
    public int Last7Days { get; set; }
    public int Successful { get; set; }
    public int Failed { get; set; }
    public double AvgDurationMs { get; set; }
}

public class OpsCommandResult
{
    public string CommandId { get; set; } = string.Empty;
    public string MachineId { get; set; } = string.Empty;
    public string? AppId { get; set; }
    public bool Success { get; set; }
    public double DurationMs { get; set; }
    public DateTime DateCreated { get; set; }
    public string OutputSnippet { get; set; } = string.Empty;
}

public class OpsSystemLog
{
    public long Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string LogLevel { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string? MachineId { get; set; }
    public string Category { get; set; } = string.Empty;
    public string EventName { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

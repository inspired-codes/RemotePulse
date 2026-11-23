using System;
using System.Linq;
using System.Net;
using System.Text;

namespace InspiredCodes.RemotePulse.HubServer.Dashboard;

public static class OpsDashboardRenderer
{
    public static string RenderHtml(OpsDashboardData data, string token)
    {
        var sb = new StringBuilder(16384);

        int onlineClients = data.Clients.Count(c => c.Health == "Online");
        int totalClients = data.Clients.Count;
        int totalCommands = data.Throughput.TotalCommands;
        int last24h = data.Throughput.Last24Hours;
        int last1h = data.Throughput.Last1Hour;
        int successful = data.Throughput.Successful;
        int failed = data.Throughput.Failed;
        double successRate = (successful + failed) > 0 ? Math.Round((double)successful / (successful + failed) * 100, 1) : 100.0;
        double avgDuration = data.Throughput.AvgDurationMs;

        sb.Append($@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>RemotePulse Ops Dashboard</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --heading: #f0f6fc;
            --green-bg: #1f6f3a;
            --green-text: #3fb950;
            --yellow-bg: #744210;
            --yellow-text: #d29922;
            --red-bg: #8c1e22;
            --red-text: #f85149;
            --blue-text: #58a6ff;
            --blue-bg: #1f3a5f;
            --accent: #238636;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            padding: 1.5rem;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            padding-bottom: 1.25rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .brand h1 {{
            font-size: 1.4rem;
            font-weight: 700;
            color: var(--heading);
        }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 9999px;
            text-transform: uppercase;
        }}
        .badge-env {{
            background: var(--blue-bg);
            color: var(--blue-text);
            border: 1px solid rgba(88, 166, 255, 0.3);
        }}
        .controls {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .btn {{
            background: #21262d;
            color: var(--heading);
            border: 1px solid var(--border);
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }}
        .btn:hover {{ background: #30363d; }}
        .btn-primary {{
            background: var(--accent);
            border-color: rgba(240, 246, 252, 0.1);
        }}
        .btn-primary:hover {{ background: #2ea043; }}
        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }}
        .status-dot.active {{ background: #3fb950; box-shadow: 0 0 8px #3fb950; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .card-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.4rem;
            font-weight: 600;
        }}
        .card-value {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--heading);
            display: flex;
            align-items: baseline;
            gap: 0.5rem;
        }}
        .card-subtext {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.4rem;
        }}
        .section-title {{
            font-size: 1.15rem;
            font-weight: 600;
            color: var(--heading);
            margin-bottom: 0.75rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .client-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .client-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        .client-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .machine-id {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--blue-text);
            word-break: break-all;
        }}
        .client-details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.5rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }}
        .detail-item strong {{
            color: var(--text);
        }}
        .badge-online {{ background: var(--green-bg); color: var(--green-text); }}
        .badge-degraded {{ background: var(--yellow-bg); color: var(--yellow-text); }}
        .badge-offline {{ background: var(--red-bg); color: var(--red-text); }}
        .table-wrap {{
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 2rem;
            background: var(--card-bg);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.85rem;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #1c2128;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
        .mono {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.8rem;
        }}
        .snippet {{
            max-width: 320px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: var(--text-muted);
        }}
        .filter-bar {{
            display: flex;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
        }}
        .filter-input {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-size: 0.85rem;
        }}
        .filter-input:focus {{
            outline: none;
            border-color: var(--blue-text);
        }}
        .text-success {{ color: var(--green-text); }}
        .text-danger {{ color: var(--red-text); }}
        .text-muted {{ color: var(--text-muted); }}
    </style>
</head>
<body>
    <header>
        <div class=""brand"">
            <span class=""status-dot active""></span>
            <h1>RemotePulse Ops</h1>
            <span class=""badge badge-env"">{WebUtility.HtmlEncode(data.Environment)}</span>
        </div>
        <div class=""controls"">
            <span id=""status-label"" class=""text-muted mono"">Server: {data.ServerTimeUtc:yyyy-MM-dd HH:mm:ss} UTC</span>
            <label style=""display: flex; align-items: center; gap: 0.35rem; font-size: 0.85rem; cursor: pointer;"">
                <input type=""checkbox"" id=""auto-refresh"" checked> Live (5s)
            </label>
            <button class=""btn"" onclick=""refreshData()"">🔄 Refresh Now</button>
        </div>
    </header>

    <div class=""stats-grid"">
        <div class=""card"">
            <div class=""card-label"">Connected Workers</div>
            <div class=""card-value""><span id=""stat-online"">{onlineClients}</span> <span style=""font-size: 1rem; color: var(--text-muted);"">/ <span id=""stat-total"">{totalClients}</span></span></div>
            <div class=""card-subtext"">Workers online and reporting heartbeat</div>
        </div>
        <div class=""card"">
            <div class=""card-label"">Command Volume</div>
            <div class=""card-value"" id=""stat-cmds-24h"">{last24h}</div>
            <div class=""card-subtext"">Past 24h &bull; <span id=""stat-cmds-1h"">{last1h}</span> in last 1h &bull; <span id=""stat-cmds-total"">{totalCommands}</span> all-time</div>
        </div>
        <div class=""card"">
            <div class=""card-label"">Success Rate</div>
            <div class=""card-value"" id=""stat-success-rate"">{successRate}%</div>
            <div class=""card-subtext""><span class=""text-success"" id=""stat-success-count"">{successful}</span> succeeded &bull; <span class=""text-danger"" id=""stat-failed-count"">{failed}</span> failed</div>
        </div>
        <div class=""card"">
            <div class=""card-label"">Average Duration</div>
            <div class=""card-value""><span id=""stat-avg-duration"">{avgDuration}</span> <span style=""font-size: 1rem; color: var(--text-muted);"">ms</span></div>
            <div class=""card-subtext"">Average command execution latency</div>
        </div>
    </div>

    <div class=""section-title"">
        <span>Workers &amp; Clients</span>
        <span class=""mono text-muted"" style=""font-size: 0.85rem;"">{totalClients} registered</span>
    </div>
    <div class=""client-grid"" id=""clients-container"">");

        if (data.Clients.Count == 0)
        {
            sb.Append(@"<div class=""client-card"" style=""grid-column: 1 / -1; text-align: center; color: var(--text-muted);"">No clients registered yet.</div>");
        }
        else
        {
            foreach (var c in data.Clients)
            {
                string badgeClass = c.Health switch
                {
                    "Online" => "badge-online",
                    "Degraded" => "badge-degraded",
                    _ => "badge-offline"
                };
                string ageText = c.AgeSeconds.HasValue ? $"{c.AgeSeconds.Value:F0}s ago" : "Never";
                string appsText = c.PairedApps.Count > 0 ? string.Join(", ", c.PairedApps) : "Unpaired";

                sb.Append($@"
        <div class=""client-card"">
            <div class=""client-header"">
                <span class=""machine-id"" title=""{WebUtility.HtmlEncode(c.MachineId)}"">{WebUtility.HtmlEncode(c.MachineId.Length > 18 ? c.MachineId.Substring(0, 18) + "..." : c.MachineId)}</span>
                <span class=""badge {badgeClass}"">{WebUtility.HtmlEncode(c.Health)}</span>
            </div>
            <div class=""client-details"">
                <div class=""detail-item"">Last Seen: <strong>{ageText}</strong></div>
                <div class=""detail-item"">Cadence: <strong>{c.PollIntervalSeconds}s</strong></div>
                <div class=""detail-item"">Missed Polls: <strong>{c.MissedPolls?.ToString() ?? "N/A"}</strong></div>
                <div class=""detail-item"">Mobile: <strong>{WebUtility.HtmlEncode(appsText)}</strong></div>
            </div>
        </div>");
            }
        }

        sb.Append($@"
    </div>

    <div class=""section-title"">
        <span>Recent Executed Commands</span>
        <span class=""mono text-muted"" style=""font-size: 0.85rem;"">Last 20</span>
    </div>
    <div class=""table-wrap"">
        <table>
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Status</th>
                    <th>Machine ID</th>
                    <th>Command ID</th>
                    <th>Duration</th>
                    <th>Output Snippet</th>
                </tr>
            </thead>
            <tbody id=""commands-tbody"">");

        if (data.RecentCommands.Count == 0)
        {
            sb.Append(@"<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">No executed commands found.</td></tr>");
        }
        else
        {
            foreach (var cmd in data.RecentCommands)
            {
                string statusBadge = cmd.Success
                    ? @"<span class=""badge badge-online"">SUCCESS</span>"
                    : @"<span class=""badge badge-offline"">FAILED</span>";
                sb.Append($@"
                <tr>
                    <td class=""mono"">{cmd.DateCreated:yyyy-MM-dd HH:mm:ss}</td>
                    <td>{statusBadge}</td>
                    <td class=""mono"">{WebUtility.HtmlEncode(cmd.MachineId.Length > 12 ? cmd.MachineId.Substring(0, 12) + "..." : cmd.MachineId)}</td>
                    <td class=""mono"">{WebUtility.HtmlEncode(cmd.CommandId)}</td>
                    <td class=""mono"">{cmd.DurationMs:F1} ms</td>
                    <td class=""mono snippet"" title=""{WebUtility.HtmlEncode(cmd.OutputSnippet)}"">{WebUtility.HtmlEncode(cmd.OutputSnippet)}</td>
                </tr>");
            }
        }

        sb.Append($@"
            </tbody>
        </table>
    </div>

    <div class=""section-title"">
        <span>System &amp; Telemetry Logs</span>
        <span class=""mono text-muted"" style=""font-size: 0.85rem;"">Last 50</span>
    </div>
    <div class=""filter-bar"">
        <input type=""text"" id=""log-search"" class=""filter-input"" placeholder=""Search logs..."" oninput=""filterLogs()"">
        <select id=""log-level-filter"" class=""filter-input"" onchange=""filterLogs()"">
            <option value="""">All Levels</option>
            <option value=""Information"">Information</option>
            <option value=""Warning"">Warning</option>
            <option value=""Error"">Error</option>
        </select>
    </div>
    <div class=""table-wrap"">
        <table>
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Level</th>
                    <th>Source</th>
                    <th>Machine ID</th>
                    <th>Event</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody id=""logs-tbody"">");

        if (data.RecentLogs.Count == 0)
        {
            sb.Append(@"<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">No system logs recorded yet.</td></tr>");
        }
        else
        {
            foreach (var log in data.RecentLogs)
            {
                string levelBadge = log.LogLevel switch
                {
                    "Error" or "Critical" => @"<span class=""badge badge-offline"">" + WebUtility.HtmlEncode(log.LogLevel) + "</span>",
                    "Warning" => @"<span class=""badge badge-degraded"">" + WebUtility.HtmlEncode(log.LogLevel) + "</span>",
                    _ => @"<span class=""badge badge-env"">" + WebUtility.HtmlEncode(log.LogLevel) + "</span>"
                };

                sb.Append($@"
                <tr class=""log-row"" data-level=""{WebUtility.HtmlEncode(log.LogLevel)}"" data-text=""{WebUtility.HtmlEncode((log.Message + " " + log.Category + " " + log.EventName + " " + log.MachineId).ToLowerInvariant())}"">
                    <td class=""mono"">{log.Timestamp:yyyy-MM-dd HH:mm:ss}</td>
                    <td>{levelBadge}</td>
                    <td class=""mono"">{WebUtility.HtmlEncode(log.Source)}</td>
                    <td class=""mono"">{WebUtility.HtmlEncode(log.MachineId ?? "-")}</td>
                    <td class=""mono text-muted"">{WebUtility.HtmlEncode(log.Category + (string.IsNullOrEmpty(log.EventName) ? "" : "/" + log.EventName))}</td>
                    <td style=""word-break: break-word;"">{WebUtility.HtmlEncode(log.Message)}</td>
                </tr>");
            }
        }

        sb.Append($@"
            </tbody>
        </table>
    </div>

    <script>
        const TOKEN = {System.Text.Json.JsonSerializer.Serialize(token)};
        let refreshInterval = null;

        function escapeHtml(str) {{
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/""/g, '&quot;');
        }}

        async function refreshData() {{
            try {{
                const url = '/ops/metrics' + (TOKEN ? ('?token=' + encodeURIComponent(TOKEN)) : '');
                const res = await fetch(url);
                if (!res.ok) {{
                    document.getElementById('status-label').textContent = 'Error: ' + res.status + ' ' + res.statusText;
                    return;
                }}
                const data = await res.json();
                renderDashboard(data);
            }} catch (e) {{
                document.getElementById('status-label').textContent = 'Update error: ' + e.message;
            }}
        }}

        function renderDashboard(data) {{
            document.getElementById('status-label').textContent = 'Updated: ' + data.serverTimeUtc.replace('T', ' ').substring(0, 19) + ' UTC';

            const online = data.clients.filter(c => c.health === 'Online').length;
            document.getElementById('stat-online').textContent = online;
            document.getElementById('stat-total').textContent = data.clients.length;
            document.getElementById('stat-cmds-24h').textContent = data.throughput.last24Hours;
            document.getElementById('stat-cmds-1h').textContent = data.throughput.last1Hour;
            document.getElementById('stat-cmds-total').textContent = data.throughput.totalCommands;

            const totalRated = data.throughput.successful + data.throughput.failed;
            const rate = totalRated > 0 ? ((data.throughput.successful / totalRated) * 100).toFixed(1) : '100.0';
            document.getElementById('stat-success-rate').textContent = rate + '%';
            document.getElementById('stat-success-count').textContent = data.throughput.successful;
            document.getElementById('stat-failed-count').textContent = data.throughput.failed;
            document.getElementById('stat-avg-duration').textContent = data.throughput.avgDurationMs;

            // Clients
            const cContainer = document.getElementById('clients-container');
            if (data.clients.length === 0) {{
                cContainer.innerHTML = '<div class=""client-card"" style=""grid-column: 1 / -1; text-align: center; color: var(--text-muted);"">No clients registered yet.</div>';
            }} else {{
                cContainer.innerHTML = data.clients.map(c => {{
                    const badgeClass = c.health === 'Online' ? 'badge-online' : (c.health === 'Degraded' ? 'badge-degraded' : 'badge-offline');
                    const ageText = c.ageSeconds !== null && c.ageSeconds !== undefined ? (c.ageSeconds.toFixed(0) + 's ago') : 'Never';
                    const appsText = c.pairedApps && c.pairedApps.length > 0 ? c.pairedApps.join(', ') : 'Unpaired';
                    const shortId = c.machineId.length > 18 ? c.machineId.substring(0, 18) + '...' : c.machineId;
                    return `
                    <div class=""client-card"">
                        <div class=""client-header"">
                            <span class=""machine-id"" title=""${{escapeHtml(c.machineId)}}"">${{escapeHtml(shortId)}}</span>
                            <span class=""badge ${{badgeClass}}"">${{escapeHtml(c.health)}}</span>
                        </div>
                        <div class=""client-details"">
                            <div class=""detail-item"">Last Seen: <strong>${{escapeHtml(ageText)}}</strong></div>
                            <div class=""detail-item"">Cadence: <strong>${{c.pollIntervalSeconds}}s</strong></div>
                            <div class=""detail-item"">Missed Polls: <strong>${{c.missedPolls !== null ? c.missedPolls : 'N/A'}}</strong></div>
                            <div class=""detail-item"">Mobile: <strong>${{escapeHtml(appsText)}}</strong></div>
                        </div>
                    </div>`;
                }}).join('');
            }}

            // Commands
            const cmdBody = document.getElementById('commands-tbody');
            if (data.recentCommands.length === 0) {{
                cmdBody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">No executed commands found.</td></tr>';
            }} else {{
                cmdBody.innerHTML = data.recentCommands.map(cmd => {{
                    const badge = cmd.success ? '<span class=""badge badge-online"">SUCCESS</span>' : '<span class=""badge badge-offline"">FAILED</span>';
                    const dateStr = cmd.dateCreated.replace('T', ' ').substring(0, 19);
                    const shortMach = cmd.machineId.length > 12 ? cmd.machineId.substring(0, 12) + '...' : cmd.machineId;
                    return `<tr>
                        <td class=""mono"">${{dateStr}}</td>
                        <td>${{badge}}</td>
                        <td class=""mono"">${{escapeHtml(shortMach)}}</td>
                        <td class=""mono"">${{escapeHtml(cmd.commandId)}}</td>
                        <td class=""mono"">${{cmd.durationMs.toFixed(1)}} ms</td>
                        <td class=""mono snippet"" title=""${{escapeHtml(cmd.outputSnippet)}}"">${{escapeHtml(cmd.outputSnippet)}}</td>
                    </tr>`;
                }}).join('');
            }}

            // Logs
            const logsBody = document.getElementById('logs-tbody');
            if (data.recentLogs.length === 0) {{
                logsBody.innerHTML = '<tr><td colspan=""6"" style=""text-align: center; color: var(--text-muted);"">No system logs recorded yet.</td></tr>';
            }} else {{
                logsBody.innerHTML = data.recentLogs.map(l => {{
                    const levelClass = (l.logLevel === 'Error' || l.logLevel === 'Critical') ? 'badge-offline' : (l.logLevel === 'Warning' ? 'badge-degraded' : 'badge-env');
                    const dateStr = l.timestamp.replace('T', ' ').substring(0, 19);
                    const catText = l.category + (l.eventName ? '/' + l.eventName : '');
                    const rowText = (l.message + ' ' + catText + ' ' + (l.machineId || '')).toLowerCase();
                    return `<tr class=""log-row"" data-level=""${{escapeHtml(l.logLevel)}}"" data-text=""${{escapeHtml(rowText)}}"">
                        <td class=""mono"">${{dateStr}}</td>
                        <td><span class=""badge ${{levelClass}}"">${{escapeHtml(l.logLevel)}}</span></td>
                        <td class=""mono"">${{escapeHtml(l.source)}}</td>
                        <td class=""mono"">${{escapeHtml(l.machineId || '-')}}</td>
                        <td class=""mono text-muted"">${{escapeHtml(catText)}}</td>
                        <td style=""word-break: break-word;"">${{escapeHtml(l.message)}}</td>
                    </tr>`;
                }}).join('');
                filterLogs();
            }}
        }}

        function filterLogs() {{
            const search = (document.getElementById('log-search').value || '').toLowerCase();
            const level = document.getElementById('log-level-filter').value;
            const rows = document.querySelectorAll('.log-row');
            rows.forEach(r => {{
                const rLevel = r.getAttribute('data-level');
                const rText = r.getAttribute('data-text');
                const matchLevel = !level || rLevel === level;
                const matchText = !search || rText.includes(search);
                r.style.display = (matchLevel && matchText) ? '' : 'none';
            }});
        }}

        function setupAutoRefresh() {{
            const checkbox = document.getElementById('auto-refresh');
            if (checkbox.checked) {{
                if (!refreshInterval) {{
                    refreshInterval = setInterval(refreshData, 5000);
                }}
            }} else {{
                if (refreshInterval) {{
                    clearInterval(refreshInterval);
                    refreshInterval = null;
                }}
            }}
        }}

        document.getElementById('auto-refresh').addEventListener('change', setupAutoRefresh);
        setupAutoRefresh();
    </script>
</body>
</html>");

        return sb.ToString();
    }
}

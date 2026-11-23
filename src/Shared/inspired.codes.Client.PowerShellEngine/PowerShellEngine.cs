using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.Client.PowerShellEngine;

public sealed class PowerShellEngine : IPowerShellEngine
{
    private readonly string _machineId;

    /// <summary>
    /// Initializes a new instance of the <see cref="PowerShellEngine"/> class.
    /// </summary>
    /// <param name="machineId">A persistent, stable machine ID identifying this client device.</param>
    public PowerShellEngine(string machineId)
    {
        if (string.IsNullOrWhiteSpace(machineId))
        {
            throw new ArgumentException("Machine ID cannot be null or empty.", nameof(machineId));
        }
        _machineId = machineId;
    }

    /// <summary>
    /// Best-effort enables <c>SeShutdownPrivilege</c> on the current process token so that
    /// <c>Restart-Computer</c>/<c>Stop-Computer</c> succeed when a script runs directly as the
    /// Worker's own identity (<see cref="ExecutionMode.RunWithHighestLocalPrivileges"/>, typically
    /// <c>NT AUTHORITY\SYSTEM</c>). LocalSystem's token holds this privilege, but Windows starts
    /// every privilege disabled regardless of identity - it must be explicitly enabled via
    /// <c>AdjustTokenPrivileges</c> before a shutdown/restart API call will succeed. Safe to call
    /// from a non-elevated account or a non-Windows OS (a no-op there) - failures are swallowed,
    /// matching <see cref="ExecuteScriptAsync"/>'s own best-effort call to this on Windows.
    /// </summary>
    public static void EnsureShutdownPrivilege()
    {
        if (OperatingSystem.IsWindows())
        {
            ImpersonationHelper.TryEnableCurrentProcessPrivilege(ImpersonationHelper.SE_SHUTDOWN_NAME);
        }
    }

    /// <inheritdoc/>
    public async Task<PowerShellResult> ExecuteScriptAsync(string script, ExecutionMode executionMode, TimeSpan? timeout = null)
    {
        if (script == null)
        {
            throw new ArgumentNullException(nameof(script));
        }

        if (!Enum.IsDefined(executionMode))
        {
            throw new ArgumentOutOfRangeException(nameof(executionMode), executionMode, $"Undefined ExecutionMode {executionMode}.");
        }

        Stopwatch stopwatch = Stopwatch.StartNew();

        // Enable SeShutdownPrivilege before any execution path so Restart-Computer/Stop-Computer
        // work under RunWithHighestLocalPrivileges (the only mode that runs as SYSTEM without
        // impersonating). Harmless no-op for the other modes.
        EnsureShutdownPrivilege();

        // RunWithHighestLocalPrivileges never impersonates - it always runs as the Worker's own
        // identity (typically NT AUTHORITY\SYSTEM). The other two modes need the active
        // interactive user's token when we're currently running as SYSTEM.
        bool requiresActiveUserToken = executionMode != ExecutionMode.RunWithHighestLocalPrivileges;

        if (OperatingSystem.IsWindows())
        {
            bool isSystem = WindowsIdentity.GetCurrent().IsSystem;

            if (requiresActiveUserToken && isSystem)
            {
                if (!ImpersonationHelper.CanImpersonateActiveUser())
                {
                    string violationMsg = "Security Boundary Violation: Cannot execute user-mode script. No active interactive user session is available to impersonate, and executing under NT AUTHORITY\\SYSTEM is restricted for non-admin payloads.";
                    return new PowerShellResult
                    {
                        MachineId = _machineId,
                        Success = false,
                        Error = violationMsg,
                        CombinedOutput = $"[SECURITY ERROR] {violationMsg}",
                        Duration = stopwatch.Elapsed
                    };
                }

                try
                {
                    if (executionMode == ExecutionMode.RunInteractiveAsCurrentUser)
                    {
                        // Launches a new process inside the active session (CreateProcessAsUser,
                        // attached to winsta0\default) so it has UI capability, e.g. a toast.
                        // Thread impersonation alone can't do this - it never leaves Session 0.
                        return await ImpersonationHelper.RunInteractiveProcessAsync(script, _machineId, timeout).ConfigureAwait(false);
                    }

                    return await ImpersonationHelper.RunAsActiveUserAsync(async () =>
                    {
                        return await ExecuteInternalAsync(script, timeout).ConfigureAwait(false);
                    }).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    string impError = $"Impersonation failed: {ex.Message}";
                    return new PowerShellResult
                    {
                        MachineId = _machineId,
                        Success = false,
                        Error = impError,
                        CombinedOutput = $"[SECURITY ERROR] {impError}",
                        Duration = stopwatch.Elapsed,
                        Exception = ex
                    };
                }
            }
        }

        // Execute in current context (User Context, or SYSTEM if RunWithHighestLocalPrivileges was requested)
        try
        {
            return await ExecuteInternalAsync(script, timeout).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new PowerShellResult
            {
                MachineId = _machineId,
                Success = false,
                Error = $"Execution initiation failed: {ex.Message}",
                CombinedOutput = $"[EXCEPTION] {ex.Message}",
                Duration = stopwatch.Elapsed,
                Exception = ex
            };
        }
    }

    private async Task<PowerShellResult> ExecuteInternalAsync(string script, TimeSpan? timeout)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        
        List<string> outputLines = new List<string>();
        List<string> errorLines = new List<string>();
        List<string> warningLines = new List<string>();
        List<string> infoLines = new List<string>();
        List<string> verboseLines = new List<string>();
        List<string> debugLines = new List<string>();
        StringBuilder combinedBuilder = new StringBuilder();

        Runspace? runspace = null;
        PowerShell? ps = null;
        bool isHung = false;

        try
        {
            // Set up in-process session state with standard PowerShell cmdlets loaded
            InitialSessionState iss = InitialSessionState.CreateDefault();

            // Execution policy is a Windows-only concept: the setter throws
            // PlatformNotSupportedException for RemoteSigned/AllSigned/Restricted anywhere else.
            // On Linux/macOS there is nothing to constrain, so leave the default untouched.
            if (OperatingSystem.IsWindows())
            {
                iss.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.RemoteSigned;
            }

            runspace = RunspaceFactory.CreateRunspace(iss);
            // Run the pipeline on the calling thread-pool thread instead of a PowerShell-owned foreground
            // thread, so a script stuck past its timeout can't keep the Worker process alive at service stop.
            runspace.ThreadOptions = PSThreadOptions.UseCurrentThread;
            runspace.Open();

            ps = PowerShell.Create();
            ps.Runspace = runspace;
            ps.AddScript(script);

            // Execute script
            Collection<PSObject> results;
            if (timeout.HasValue)
            {
                using var cts = new CancellationTokenSource(timeout.Value);
                var invokeTask = Task.Run(() => ps.Invoke());
                var completedTask = await Task.WhenAny(invokeTask, Task.Delay(timeout.Value, cts.Token));
                if (completedTask != invokeTask)
                {
                    isHung = true;
                    // Stop() blocks until the pipeline stops, which never happens if the script is stuck in a
                    // .NET or native call (e.g. a MessageBox in Session 0) - request the stop without waiting.
                    var stuckPs = ps;
                    _ = Task.Run(() => { try { stuckPs.Stop(); } catch { } });
                    throw new TimeoutException($"Script execution timed out after {timeout.Value.TotalSeconds} seconds.");
                }
                cts.Cancel();
                results = await invokeTask;
            }
            else
            {
                results = await Task.Run(() => ps.Invoke());
            }

            // 1. Capture Standard Output Pipeline Results
            foreach (PSObject result in results)
            {
                if (result != null)
                {
                    string str = result.ToString();
                    outputLines.Add(str);
                    combinedBuilder.AppendLine(str);
                }
            }

            // 2. Capture and format streams in execution order/details
            if (ps.Streams.Error.Count > 0)
            {
                foreach (ErrorRecord err in ps.Streams.Error)
                {
                    if (err != null)
                    {
                        string str = err.ToString();
                        errorLines.Add(str);
                        combinedBuilder.AppendLine($"[ERROR] {str}");
                    }
                }
            }

            if (ps.Streams.Warning.Count > 0)
            {
                foreach (WarningRecord warn in ps.Streams.Warning)
                {
                    if (warn != null)
                    {
                        string str = warn.ToString();
                        warningLines.Add(str);
                        combinedBuilder.AppendLine($"[WARNING] {str}");
                    }
                }
            }

            if (ps.Streams.Information.Count > 0)
            {
                foreach (InformationRecord info in ps.Streams.Information)
                {
                    if (info != null)
                    {
                        string str = info.MessageData?.ToString() ?? info.ToString();
                        infoLines.Add(str);
                        combinedBuilder.AppendLine($"[INFO] {str}");
                    }
                }
            }

            if (ps.Streams.Verbose.Count > 0)
            {
                foreach (VerboseRecord verb in ps.Streams.Verbose)
                {
                    if (verb != null)
                    {
                        string str = verb.ToString();
                        verboseLines.Add(str);
                        combinedBuilder.AppendLine($"[VERBOSE] {str}");
                    }
                }
            }

            if (ps.Streams.Debug.Count > 0)
            {
                foreach (DebugRecord dbg in ps.Streams.Debug)
                {
                    if (dbg != null)
                    {
                        string str = dbg.ToString();
                        debugLines.Add(str);
                        combinedBuilder.AppendLine($"[DEBUG] {str}");
                    }
                }
            }

            bool success = !ps.HadErrors && errorLines.Count == 0;

            return new PowerShellResult
            {
                MachineId = _machineId,
                Success = success,
                Output = string.Join(Environment.NewLine, outputLines),
                Error = string.Join(Environment.NewLine, errorLines),
                CombinedOutput = combinedBuilder.ToString().TrimEnd(),
                OutputLines = outputLines.AsReadOnly(),
                ErrorLines = errorLines.AsReadOnly(),
                WarningLines = warningLines.AsReadOnly(),
                InformationLines = infoLines.AsReadOnly(),
                VerboseLines = verboseLines.AsReadOnly(),
                DebugLines = debugLines.AsReadOnly(),
                Duration = stopwatch.Elapsed
            };
        }
        catch (Exception ex)
        {
            combinedBuilder.AppendLine($"[EXCEPTION] {ex.Message}");
            return new PowerShellResult
            {
                MachineId = _machineId,
                Success = false,
                Error = ex.Message,
                CombinedOutput = combinedBuilder.ToString().TrimEnd(),
                OutputLines = outputLines.AsReadOnly(),
                ErrorLines = new List<string>(errorLines) { ex.Message }.AsReadOnly(),
                WarningLines = warningLines.AsReadOnly(),
                InformationLines = infoLines.AsReadOnly(),
                VerboseLines = verboseLines.AsReadOnly(),
                DebugLines = debugLines.AsReadOnly(),
                Duration = stopwatch.Elapsed,
                Exception = ex
            };
        }
        finally
        {
            if (isHung)
            {
                // When a script is stuck in an unmanaged Win32/COM modal loop (e.g. WScript.Shell.Popup,
                // MessageBox, or native blocking wait), synchronous Runspace.Dispose() calls Runspace.Close()
                // which waits indefinitely for the pipeline to finish, deadlocking the Worker thread.
                // Offload disposal to a detached background task so the Worker remains responsive and returns
                // the TimeoutException immediately.
                var detachedPs = ps;
                var detachedRunspace = runspace;
                _ = Task.Run(() =>
                {
                    try { detachedPs?.Dispose(); } catch { }
                    try { detachedRunspace?.Dispose(); } catch { }
                });
            }
            else
            {
                try { ps?.Dispose(); } catch { }
                try { runspace?.Dispose(); } catch { }
            }
        }
    }
}

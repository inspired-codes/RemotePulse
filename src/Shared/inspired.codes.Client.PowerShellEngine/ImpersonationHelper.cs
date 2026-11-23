using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace InspiredCodes.Client.PowerShellEngine;

internal static class ImpersonationHelper
{
    private const uint INVALID_SESSION_ID = 0xFFFFFFFF;

    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_IMPERSONATE = 0x0004;
    private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;

    private const uint SecurityImpersonation = 2;
    private const uint TokenImpersonation = 2;
    private const uint TokenPrimary = 1;

    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;
    private const string SE_ASSIGN_PRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
    private const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
    internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";

    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NO_WINDOW = 0x08000000;

    private const uint INFINITE = 0xFFFFFFFF;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private const uint WAIT_FAILED = 0xFFFFFFFF;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        uint impersonationLevel,
        uint tokenType,
        out IntPtr phNewToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLengthInBytes,
        IntPtr PreviousState,
        IntPtr ReturnLengthInBytes);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    private sealed class InteractiveResultDto
    {
        public bool Success { get; set; }
        public string Output { get; set; } = string.Empty;
        public string Error { get; set; } = string.Empty;
        public string CombinedOutput { get; set; } = string.Empty;
        public double DurationMs { get; set; }
    }

    /// <summary>
    /// Checks if we can obtain a token for the active console user.
    /// </summary>
    public static bool CanImpersonateActiveUser()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return false;
        }

        uint sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == INVALID_SESSION_ID)
        {
            return false;
        }

        IntPtr userToken = IntPtr.Zero;
        try
        {
            if (WTSQueryUserToken(sessionId, out userToken))
            {
                return true;
            }
        }
        catch
        {
            // Suppress P/Invoke errors
        }
        finally
        {
            if (userToken != IntPtr.Zero)
            {
                CloseHandle(userToken);
            }
        }

        return false;
    }

    /// <summary>
    /// Executes the specified asynchronous action under the security context of the active interactive desktop user.
    /// </summary>
    public static async Task<T> RunAsActiveUserAsync<T>(Func<Task<T>> action)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return await action().ConfigureAwait(false);
        }

        IntPtr userToken = IntPtr.Zero;
        IntPtr duplicatedToken = IntPtr.Zero;

        try
        {
            uint sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == INVALID_SESSION_ID)
            {
                throw new InvalidOperationException("No active console session found to impersonate.");
            }

            if (!WTSQueryUserToken(sessionId, out userToken))
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"WTSQueryUserToken failed for Session ID {sessionId} with Win32 Error {error}. Make sure the service is running with elevated administrative or SYSTEM privileges.");
            }

            uint desiredAccess = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE;
            if (!DuplicateTokenEx(userToken, desiredAccess, IntPtr.Zero, SecurityImpersonation, TokenImpersonation, out duplicatedToken))
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"DuplicateTokenEx failed with Win32 Error {error}.");
            }

            using SafeAccessTokenHandle safeHandle = new SafeAccessTokenHandle(duplicatedToken);
            return await WindowsIdentity.RunImpersonatedAsync(safeHandle, action).ConfigureAwait(false);
        }
        finally
        {
            if (userToken != IntPtr.Zero)
            {
                CloseHandle(userToken);
            }
        }
    }

    /// <summary>
    /// Launches a new process inside the active interactive user's session (attached to
    /// <c>winsta0\default</c>) and runs the given script there, so it has UI capability (e.g. a
    /// toast) that thread impersonation alone can't provide - <see cref="RunAsActiveUserAsync{T}"/>
    /// stays in the caller's own (Session 0) process and never gets an interactive desktop.
    /// </summary>
    /// <remarks>
    /// Output/error text is captured via a best-effort wrapper script that writes a JSON result
    /// file after the script finishes, rather than via stdout/stderr pipes - handle inheritance
    /// across <c>CreateProcessAsUser</c> into a different session is unreliable. As a result, only
    /// <see cref="PowerShellResult.Output"/>/<see cref="PowerShellResult.Error"/>/
    /// <see cref="PowerShellResult.CombinedOutput"/> are populated; the per-stream Warning/
    /// Information/Verbose/Debug line collections are always empty for this mode.
    /// </remarks>
    public static async Task<PowerShellResult> RunInteractiveProcessAsync(string script, string machineId, TimeSpan? timeout)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException("Interactive session launch is only supported on Windows.");
        }

        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr envBlock = IntPtr.Zero;
        string? workDir = null;
        PROCESS_INFORMATION pi = default;

        try
        {
            EnableCurrentProcessPrivilege(SE_ASSIGN_PRIMARYTOKEN_NAME);
            EnableCurrentProcessPrivilege(SE_INCREASE_QUOTA_NAME);

            uint sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == INVALID_SESSION_ID)
            {
                throw new InvalidOperationException("No active console session found to launch into.");
            }

            if (!WTSQueryUserToken(sessionId, out userToken))
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"WTSQueryUserToken failed for Session ID {sessionId} with Win32 Error {error}.");
            }

            uint primaryAccess = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
            if (!DuplicateTokenEx(userToken, primaryAccess, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out primaryToken))
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"DuplicateTokenEx (primary) failed with Win32 Error {error}.");
            }

            if (!CreateEnvironmentBlock(out envBlock, primaryToken, false))
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"CreateEnvironmentBlock failed with Win32 Error {error}.");
            }

            // Write the script into the target user's own temp directory via thread impersonation,
            // so the folder/files come out owned by that user - no ACL surgery needed for the
            // interactive process to read/write there.
            workDir = await RunAsActiveUserAsync(async () =>
            {
                string dir = Path.Combine(Path.GetTempPath(), "RemotePulse-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(dir);
                await File.WriteAllTextAsync(Path.Combine(dir, "script.ps1"), script).ConfigureAwait(false);
                return dir;
            }).ConfigureAwait(false);

            string scriptPath = Path.Combine(workDir, "script.ps1");
            string resultPath = Path.Combine(workDir, "result.json");

            string wrapperCommand = BuildWrapperCommand(scriptPath, resultPath);
            string encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(wrapperCommand));

            string powershellPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            StringBuilder commandLine = new StringBuilder($"\"{powershellPath}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encodedCommand}");

            STARTUPINFO si = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = "winsta0\\default"
            };

            bool created = CreateProcessAsUser(
                primaryToken,
                null,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                envBlock,
                workDir,
                ref si,
                out pi);

            if (!created)
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"CreateProcessAsUser failed with Win32 Error {error}.");
            }

            // BUG-7: Wait directly on the process handle returned by CreateProcessAsUser to eliminate
            // the PID-reuse race condition that occurs if the process exits fast and is recycled.
            uint timeoutMs = timeout.HasValue ? (uint)Math.Max(1, timeout.Value.TotalMilliseconds) : INFINITE;
            uint waitResult = await Task.Run(() => WaitForSingleObject(pi.hProcess, timeoutMs)).ConfigureAwait(false);

            if (waitResult == WAIT_TIMEOUT)
            {
                TerminateProcess(pi.hProcess, 1);
                throw new TimeoutException($"Interactive script execution timed out after {timeout!.Value.TotalSeconds} seconds.");
            }
            if (waitResult == WAIT_FAILED)
            {
                int error = Marshal.GetLastWin32Error();
                throw new InvalidOperationException($"WaitForSingleObject failed with Win32 Error {error}.");
            }

            // BUG-8: delete script.ps1 as soon as execution finishes to minimize plaintext persistence
            if (File.Exists(scriptPath))
            {
                try { File.Delete(scriptPath); } catch { /* best-effort */ }
            }

            if (!File.Exists(resultPath))
            {
                throw new InvalidOperationException("The interactive process exited without producing a result file (it may have crashed before the wrapper script finished).");
            }

            string resultJson = await File.ReadAllTextAsync(resultPath).ConfigureAwait(false);
            InteractiveResultDto dto = JsonSerializer.Deserialize<InteractiveResultDto>(resultJson)
                ?? throw new InvalidOperationException("The interactive process's result file could not be parsed.");

            return new PowerShellResult
            {
                MachineId = machineId,
                Success = dto.Success,
                Output = dto.Output,
                Error = dto.Error,
                CombinedOutput = dto.CombinedOutput,
                Duration = TimeSpan.FromMilliseconds(dto.DurationMs)
            };
        }
        finally
        {
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
            if (workDir != null)
            {
                try { Directory.Delete(workDir, true); } catch { /* best-effort cleanup */ }
            }
        }
    }

    /// <summary>
    /// Best-effort variant of <see cref="EnableCurrentProcessPrivilege"/> - swallows failures
    /// instead of throwing, so callers that only want the privilege enabled when possible (e.g.
    /// <see cref="SE_SHUTDOWN_NAME"/> before running scripts as SYSTEM) don't need a try/catch of
    /// their own, and unit tests running under a non-admin/non-Windows account don't blow up.
    /// </summary>
    internal static bool TryEnableCurrentProcessPrivilege(string privilegeName)
    {
        try
        {
            EnableCurrentProcessPrivilege(privilegeName);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void EnableCurrentProcessPrivilege(string privilegeName)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr hToken))
        {
            throw new InvalidOperationException($"OpenProcessToken failed with Win32 Error {Marshal.GetLastWin32Error()}.");
        }

        try
        {
            if (!LookupPrivilegeValue(null, privilegeName, out LUID luid))
            {
                throw new InvalidOperationException($"LookupPrivilegeValue failed for '{privilegeName}' with Win32 Error {Marshal.GetLastWin32Error()}.");
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
            };

            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            {
                throw new InvalidOperationException($"AdjustTokenPrivileges failed for '{privilegeName}' with Win32 Error {Marshal.GetLastWin32Error()}.");
            }

            int lastError = Marshal.GetLastWin32Error();
            if (lastError == ERROR_NOT_ALL_ASSIGNED)
            {
                throw new InvalidOperationException($"Privilege '{privilegeName}' could not be assigned (ERROR_NOT_ALL_ASSIGNED). The Worker process may not be running with sufficient rights (expected NT AUTHORITY\\SYSTEM).");
            }
        }
        finally
        {
            CloseHandle(hToken);
        }
    }

    private static string BuildWrapperCommand(string scriptPath, string resultPath)
    {
        static string EscapeSingleQuoted(string s) => s.Replace("'", "''");

        return $@"
$ErrorActionPreference = 'Continue'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$outputLines = New-Object System.Collections.Generic.List[string]
$errorLines = New-Object System.Collections.Generic.List[string]
try {{
    $raw = & '{EscapeSingleQuoted(scriptPath)}' 2>&1
    foreach ($r in $raw) {{
        if ($r -is [System.Management.Automation.ErrorRecord]) {{ $errorLines.Add($r.ToString()) }}
        else {{ $outputLines.Add($r.ToString()) }}
    }}
}} catch {{
    $errorLines.Add($_.Exception.Message)
}}
$sw.Stop()
$success = ($errorLines.Count -eq 0)
$combinedParts = New-Object System.Collections.Generic.List[string]
$combinedParts.AddRange($outputLines)
foreach ($e in $errorLines) {{ $combinedParts.Add(""[ERROR] $e"") }}
$result = [PSCustomObject]@{{
    Success = $success
    Output = ($outputLines -join [Environment]::NewLine)
    Error = ($errorLines -join [Environment]::NewLine)
    CombinedOutput = ($combinedParts -join [Environment]::NewLine)
    DurationMs = $sw.Elapsed.TotalMilliseconds
}}
$result | ConvertTo-Json -Compress | Set-Content -Path '{EscapeSingleQuoted(resultPath)}' -Encoding UTF8
";
    }
}

using System;
using System.Threading.Tasks;
using Xunit;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.Client.PowerShellEngine.Tests;

public class PowerShellEngineTests
{
    private const string TestMachineId = "TEST-DEVICE-GUID-12345";
    private readonly PowerShellEngine _engine = new(TestMachineId);

    [Fact]
    public async Task ExecuteScriptAsync_UndefinedExecutionMode_ThrowsArgumentOutOfRangeException()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _engine.ExecuteScriptAsync("Write-Output 'test'", (ExecutionMode)99));
    }

    [Fact]
    public async Task ExecuteScriptAsync_SimpleCommand_ShouldReturnSuccessAndOutput()
    {
        // Also the regression guard for EnsureShutdownPrivilege(): ExecuteScriptAsync calls it on
        // every invocation before running the script, so this proves it doesn't disrupt execution.

        // Arrange
        string script = "Write-Output 'Hello from PowerShell'";

        // Act
        PowerShellResult result = await _engine.ExecuteScriptAsync(script, executionMode: ExecutionMode.RunWithHighestLocalPrivileges);

        // Assert
        Assert.True(result.Success);
        Assert.Equal(TestMachineId, result.MachineId);
        Assert.Contains("Hello from PowerShell", result.Output);
        Assert.Empty(result.Error);
        Assert.Contains("Hello from PowerShell", result.CombinedOutput);
    }

    [Fact]
    public async Task ExecuteScriptAsync_MathExpression_ShouldReturnPipelineValue()
    {
        // Arrange
        string script = "2 + 3";

        // Act
        PowerShellResult result = await _engine.ExecuteScriptAsync(script, executionMode: ExecutionMode.RunWithHighestLocalPrivileges);

        // Assert
        Assert.True(result.Success);
        Assert.Contains("5", result.Output);
        Assert.Empty(result.Error);
    }

    [Fact]
    public async Task ExecuteScriptAsync_ErrorWriting_ShouldCaptureErrors()
    {
        // Arrange
        string script = "Write-Error 'Test error message'";

        // Act
        PowerShellResult result = await _engine.ExecuteScriptAsync(script, executionMode: ExecutionMode.RunWithHighestLocalPrivileges);

        // Assert
        Assert.False(result.Success);
        Assert.Contains("Test error message", result.Error);
        Assert.Contains("[ERROR]", result.CombinedOutput);
        Assert.Single(result.ErrorLines);
    }

    [Fact]
    public void EnsureShutdownPrivilege_DoesNotThrow_RegardlessOfPlatformOrElevation()
    {
        // Best-effort by design: a non-Windows OS is a no-op, and a non-admin/non-SYSTEM Windows
        // account fails the underlying AdjustTokenPrivileges call, but TryEnableCurrentProcessPrivilege
        // swallows that - CI and local dev runs (like this one, non-Windows) must never break here.
        InspiredCodes.Client.PowerShellEngine.PowerShellEngine.EnsureShutdownPrivilege();
    }

    [Fact]
    public async Task ExecuteScriptAsync_MultipleStreams_ShouldCaptureAll()
    {
        // Arrange
        string script = @"
            $DebugPreference = 'Continue'
            $VerbosePreference = 'Continue'
            $InformationPreference = 'Continue'
            Write-Output 'OutputLine1'
            Write-Warning 'WarningLine1'
            Write-Information 'InfoLine1'
            Write-Verbose 'VerboseLine1'
            Write-Debug 'DebugLine1'
        ";

        // Act
        PowerShellResult result = await _engine.ExecuteScriptAsync(script, executionMode: ExecutionMode.RunWithHighestLocalPrivileges);

        // Assert
        Assert.True(result.Success);
        
        Assert.Contains("OutputLine1", result.OutputLines);
        Assert.Contains("WarningLine1", result.WarningLines);
        Assert.Contains("InfoLine1", result.InformationLines);
        Assert.Contains("VerboseLine1", result.VerboseLines);
        Assert.Contains("DebugLine1", result.DebugLines);
        
        Assert.Contains("[WARNING] WarningLine1", result.CombinedOutput);
        Assert.Contains("[INFO] InfoLine1", result.CombinedOutput);
        Assert.Contains("[VERBOSE] VerboseLine1", result.CombinedOutput);
        Assert.Contains("[DEBUG] DebugLine1", result.CombinedOutput);
    }

    [Fact]
    public async Task ExecuteScriptAsync_ExceptionInScript_ShouldFailGracefully()
    {
        // Arrange
        string script = "throw 'Critical exception'";

        // Act
        PowerShellResult result = await _engine.ExecuteScriptAsync(script, executionMode: ExecutionMode.RunWithHighestLocalPrivileges);

        // Assert
        Assert.False(result.Success);
        Assert.NotEmpty(result.Error);
        Assert.Contains("Critical exception", result.Error);
    }

    [Fact]
    public async Task ExecuteScriptAsync_Timeout_ShouldReturnFailureWithoutDeadlocking()
    {
        // Arrange
        string script = "Start-Sleep -Seconds 10";

        // Act
        PowerShellResult result = await _engine.ExecuteScriptAsync(
            script,
            executionMode: ExecutionMode.RunWithHighestLocalPrivileges,
            timeout: TimeSpan.FromMilliseconds(500));

        // Assert
        Assert.False(result.Success);
        Assert.Contains("timed out", result.Error);
    }

    [Fact]
    public async Task ExecuteScriptAsync_Timeout_WhenScriptBlocksInDotNetCall_StillReturns()
    {
        // A blocking .NET call (like an invisible MessageBox in Session 0) never honours a pipeline
        // stop request, unlike the Start-Sleep cmdlet above.
        string script = "[System.Threading.Thread]::Sleep(-1)";

        Task<PowerShellResult> execution = _engine.ExecuteScriptAsync(
            script,
            executionMode: ExecutionMode.RunWithHighestLocalPrivileges,
            timeout: TimeSpan.FromSeconds(1));

        Task finished = await Task.WhenAny(execution, Task.Delay(TimeSpan.FromSeconds(15)));

        Assert.True(finished == execution, "ExecuteScriptAsync did not return after its timeout - a stuck script would hang the Worker's poll loop.");
        PowerShellResult result = await execution;
        Assert.False(result.Success);
        Assert.Contains("timed out", result.Error);
    }
}

using System;
using System.IO;
using System.Linq;
using System.Management.Automation.Language;
using System.Threading.Tasks;
using Xunit;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.Client.PowerShellEngine.Tests;

/// <summary>
/// The App's predefined "Update Worker" script (src/Applications/.../App/Scripts). It is sent as
/// text and only ever parsed on the target machine, so a syntax slip would surface as a failed
/// update on a customer's PC - these tests catch it at build time instead.
/// </summary>
public class WorkerSelfUpdateScriptTests
{
    private static readonly string ScriptPath = Path.Combine(AppContext.BaseDirectory, "Update-RemotePulseWorker.ps1");

    [Fact]
    public void Script_AndTheRunnerItWritesOut_ParseWithoutErrors()
    {
        ScriptBlockAst ast = Parser.ParseFile(ScriptPath, out _, out ParseError[] errors);
        Assert.Empty(errors);

        // The detached runner is a single-quoted here-string written to disk at run time, so the
        // parse above sees it as plain text. Parse it on its own as well.
        var runner = ast.FindAll(node => node is StringConstantExpressionAst { StringConstantType: StringConstantType.SingleQuotedHereString }, true)
            .Cast<StringConstantExpressionAst>()
            .Single();
        Parser.ParseInput(runner.Value, out _, out ParseError[] runnerErrors);
        Assert.Empty(runnerErrors);
        Assert.Contains("Installer.ps1", runner.Value);
    }

    [Fact]
    public async Task Engine_ReportsFailure_WhenANativeCommandExitsNonZero_EvenWithStderrDiscarded()
    {
        // Why the next test exists. Found on the first live update (Bombus, 2026-10-20): the
        // update was scheduled fine, but "systemctl is-active" (exit 3) had already flagged
        // the result as failed.
        string script = OperatingSystem.IsWindows() ? "& cmd.exe /c exit 3 2>$null; 'after'" : "& sh -c 'exit 3' 2>$null; 'after'";

        PowerShellResult result = await new PowerShellEngine("TEST-DEVICE").ExecuteScriptAsync(script, ExecutionMode.RunWithHighestLocalPrivileges);

        Assert.Contains("after", result.Output);
        Assert.False(result.Success);
    }

    [Fact]
    public void Script_InProcessPart_OnlyRunsSystemctlCommandsThatExitZeroOnTheHappyPath()
    {
        ScriptBlockAst ast = Parser.ParseFile(ScriptPath, out _, out _);

        // The detached runner is a here-string, so these are only the commands the Worker itself
        // runs - the ones whose exit codes decide whether the App shows success.
        var systemctlCalls = ast.FindAll(node => node is CommandAst c && c.GetCommandName() == "systemctl", true)
            .Cast<CommandAst>()
            .ToList();

        Assert.NotEmpty(systemctlCalls);
        foreach (CommandAst call in systemctlCalls)
        {
            string verb = call.CommandElements[1].Extent.Text;
            if (verb == "reset-failed")
            {
                // Exits 1 when there's nothing to reset, so only for a unit known to be failed.
                Ast? node = call.Parent;
                while (node is not null and not IfStatementAst) node = node.Parent;
                var guard = Assert.IsType<IfStatementAst>(node);
                Assert.Contains("\"failed\"", guard.Clauses[0].Item1.Extent.Text);
            }
            else
            {
                Assert.Equal("show", verb);
            }
        }
    }

    [Fact]
    public async Task Script_RefusesToRunWithoutSystemOrRootRights()
    {
        // Run elevated, the script would go on to schedule a real update of this machine's
        // Worker (Bombus has one), so only the refusal path is exercised here.
        if (Environment.IsPrivilegedProcess)
        {
            Assert.Skip("Running as root/Administrator - the script would schedule a real update.");
        }

        var engine = new PowerShellEngine("TEST-DEVICE");
        PowerShellResult result = await engine.ExecuteScriptAsync(
            await File.ReadAllTextAsync(ScriptPath, TestContext.Current.CancellationToken),
            ExecutionMode.RunWithHighestLocalPrivileges);

        Assert.False(result.Success);
        Assert.Contains("must be sent with ExecutionMode RunWithHighestLocalPrivileges", result.CombinedOutput);
    }
}

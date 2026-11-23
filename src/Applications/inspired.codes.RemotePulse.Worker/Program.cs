using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using InspiredCodes.Client.PowerShellEngine;
using InspiredCodes.RemotePulse.Shared.Cryptography;

namespace InspiredCodes.RemotePulse.Worker;

/// <summary>
/// Entry bootstrapper class for the RemotePulse background client daemon.
/// Handles command-line actions for service installation, configuration, and key pairing.
/// </summary>
public static class Program
{
    /// <summary>
    /// Program execution starting point.
    /// Processes CLI flags if present, otherwise boots the Windows Service host.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    public static async Task Main(string[] args)
    {
        if (args.Length > 0 && args[0] != "--run-as-service")
        {
            string command = args[0].ToLowerInvariant();
            switch (command)
            {
                case "--install":
                    InstallService();
                    break;
                case "--uninstall":
                    UninstallService();
                    break;
                case "--start":
                    StartService();
                    break;
                case "--stop":
                    StopService();
                    break;
                case "--configure":
                    ConfigureInteractive();
                    break;
                default:
                    Console.WriteLine($"Unknown argument: {args[0]}");
                    Console.WriteLine("Available arguments: --install, --uninstall, --start, --stop, --configure");
                    break;
            }
            return;
        }

        HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

        // Enable Windows Service lifecycle integration
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = "RemotePulseWorker";
        });

        // Worker runs as a Windows Service, a systemd service, or plain foreground process
        // depending on OS, so logging can't lean on Windows Event Log (aside from it having
        // silently dropped our own categories the whole time - only the framework's own
        // lifecycle messages ever showed up there). Clear the OS-specific default providers and
        // use just Console (useful for foreground/dev runs) plus a slim cross-platform file sink
        // - tail AppPaths.GetLogFilePath() (e.g. C:\ProgramData\RemotePulse\worker.log).
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(options => options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ");
        builder.Logging.AddProvider(new FileLoggerProvider(AppPaths.GetLogFilePath()));

        // Best-effort: enable SeShutdownPrivilege once at startup so Restart-Computer/Stop-Computer
        // commands succeed later under ExecutionMode.RunWithHighestLocalPrivileges. Windows tokens
        // start every privilege disabled even for SYSTEM; PowerShellEngine also calls this per
        // execution as the actual fix, this is just an early best-effort attempt.
        PowerShellEngine.EnsureShutdownPrivilege();

        // Load configuration section
        IConfigurationSection configSection = builder.Configuration.GetSection("RemotePulse");
        string serverUrl = configSection.GetValue<string>("ServerUrl") ?? "http://localhost:5000/";
        bool allowUntrustedCertificates = configSection.GetValue<bool>("AllowUntrustedCertificates", false);
        string machineId = configSection.GetValue<string>("MachineId") ?? Guid.NewGuid().ToString();
        string keyStoragePath = configSection.GetValue<string>("KeyStoragePath") ?? AppPaths.GetKeyStoragePath();
        int pollIntervalSeconds = configSection.GetValue<int>("PollIntervalSeconds", 12);

        // Seconds the Hub may hold a poll open waiting for work. 0 falls back to fixed-interval
        // polling. Kept below the idle timeouts proxies typically impose on quiet connections.
        int longPollWaitSeconds = configSection.GetValue<int>("LongPollWaitSeconds", 25);

        // Register KeyPairManager as a Singleton and ensure keys exist/are loaded on startup
        builder.Services.AddSingleton<IKeyPairManager>(sp =>
        {
            ILogger<KeyPairManager> logger = sp.GetRequiredService<ILogger<KeyPairManager>>();
            logger.LogInformation("Initializing KeyPairManager. Key Storage Path: {Path}", keyStoragePath);
            
            KeyPairManager manager = new KeyPairManager(keyStoragePath);
            try
            {
                if (!manager.KeysExist())
                {
                    logger.LogInformation("No existing key pair found. Generating new ECDSA P-256 keys...");
                    manager.GenerateAndSaveKeys();
                    logger.LogInformation("New key pair generated and securely stored.");
                }
                else
                {
                    // A corrupt/unreadable key file must stop the service, not silently mint a
                    // new identity: this MachineId is already registered on the Hub against the
                    // old key, so a silent regenerate here looks like unexplained pairing loss.
                    logger.LogInformation("Loading existing secure key pair...");
                    manager.LoadKeys();
                    logger.LogInformation("Keys loaded successfully.");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to initialize cryptographic key pair.");
                throw;
            }

            return manager;
        });

        // Register PowerShellEngine as a Singleton
        builder.Services.AddSingleton<IPowerShellEngine>(sp => new PowerShellEngine(machineId));

        // Configure HttpClient with dev/test phase support for HTTP and untrusted SSL certificates
        builder.Services.AddHttpClient("RemotePulseHub", client =>
        {
            client.BaseAddress = new Uri(serverUrl);

            // Must comfortably exceed the long-poll window, or the client would abort its own
            // parked request before the Hub ever gets to answer it.
            client.Timeout = longPollWaitSeconds > 0
                ? TimeSpan.FromSeconds(longPollWaitSeconds + 30)
                : TimeSpan.FromSeconds(30);

            client.DefaultRequestHeaders.Add("User-Agent", "RemotePulseWorker/1.0");
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            // Allow HTTP or untrusted/self-signed SSL certificates when configured for dev/test phase
            ServerCertificateCustomValidationCallback = allowUntrustedCertificates 
                ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator 
                : null
        });

        // Register background poll service
        builder.Services.AddHostedService<PollingWorker>(sp =>
        {
            ILogger<PollingWorker> logger = sp.GetRequiredService<ILogger<PollingWorker>>();
            ILogger<LocalUiServer> localUiLogger = sp.GetRequiredService<ILogger<LocalUiServer>>();
            IHttpClientFactory httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
            IKeyPairManager keyManager = sp.GetRequiredService<IKeyPairManager>();
            IPowerShellEngine psEngine = sp.GetRequiredService<IPowerShellEngine>();

            return new PollingWorker(
                logger, 
                httpClientFactory, 
                keyManager, 
                psEngine, 
                machineId,
                pollIntervalSeconds,
                localUiLogger,
                serverUrl,
                longPollWaitSeconds: longPollWaitSeconds);
        });

        IHost host = builder.Build();
        host.Run();
    }

    private static int RunProcess(string filename, string arguments)
    {
        try
        {
            using var process = new Process();
            process.StartInfo.FileName = filename;
            process.StartInfo.Arguments = arguments;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.Start();
            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (!string.IsNullOrWhiteSpace(stdout))
            {
                Console.Write(stdout);
            }
            if (!string.IsNullOrWhiteSpace(stderr))
            {
                Console.Error.Write(stderr);
            }
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error running process {filename}: {ex.Message}");
            return -1;
        }
    }

    private static void InstallService()
    {
        string? processPath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(processPath))
        {
            Console.WriteLine("Error: Could not determine the executable path.");
            Environment.ExitCode = 1;
            return;
        }

        Console.WriteLine($"Installing service 'RemotePulseWorker' with path: {processPath}");
        int exitCode = RunProcess("sc.exe", $"create RemotePulseWorker binPath= \"\\\"{processPath}\\\" --run-as-service\" start= auto DisplayName= \"RemotePulse Worker\"");
        if (exitCode == 0)
        {
            Console.WriteLine("Service installed successfully.");
        }
        else
        {
            Console.WriteLine($"Failed to install service. sc.exe exit code: {exitCode}");
            Environment.ExitCode = exitCode;
        }
    }

    private static void UninstallService()
    {
        Console.WriteLine("Uninstalling service 'RemotePulseWorker'...");
        int exitCode = RunProcess("sc.exe", "delete RemotePulseWorker");
        if (exitCode == 0)
        {
            Console.WriteLine("Service uninstalled successfully.");
        }
        else
        {
            Console.WriteLine($"Failed to uninstall service. sc.exe exit code: {exitCode}");
            Environment.ExitCode = exitCode;
        }
    }

    private static void StartService()
    {
        Console.WriteLine("Starting service 'RemotePulseWorker'...");
        int exitCode = RunProcess("sc.exe", "start RemotePulseWorker");
        if (exitCode == 0)
        {
            Console.WriteLine("Service start command issued successfully.");
        }
        else
        {
            Console.WriteLine($"Failed to start service. sc.exe exit code: {exitCode}");
            Environment.ExitCode = exitCode;
        }
    }

    private static void StopService()
    {
        Console.WriteLine("Stopping service 'RemotePulseWorker'...");
        int exitCode = RunProcess("sc.exe", "stop RemotePulseWorker");
        if (exitCode == 0)
        {
            Console.WriteLine("Service stop command issued successfully.");
        }
        else
        {
            Console.WriteLine($"Failed to stop service. sc.exe exit code: {exitCode}");
            Environment.ExitCode = exitCode;
        }
    }

    private static void ConfigureInteractive()
    {
        Console.WriteLine("=== RemotePulse Configuration Wizard ===");
        
        string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");
        string serverUrl = "http://localhost:5000/";
        string machineId = Guid.NewGuid().ToString();
        string keyStoragePath = AppPaths.GetKeyStoragePath();
        int pollIntervalSeconds = 12;
        int longPollWaitSeconds = 25;

        if (File.Exists(configPath))
        {
            try
            {
                string json = File.ReadAllText(configPath);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("RemotePulse", out var remotePulseSection))
                {
                    if (remotePulseSection.TryGetProperty("ServerUrl", out var prop)) serverUrl = prop.GetString() ?? serverUrl;
                    if (remotePulseSection.TryGetProperty("MachineId", out var propId)) machineId = propId.GetString() ?? machineId;
                    if (remotePulseSection.TryGetProperty("KeyStoragePath", out var propPath)) keyStoragePath = propPath.GetString() ?? keyStoragePath;
                    if (remotePulseSection.TryGetProperty("PollIntervalSeconds", out var propInterval)) pollIntervalSeconds = propInterval.GetInt32();
                    if (remotePulseSection.TryGetProperty("LongPollWaitSeconds", out var propWait)) longPollWaitSeconds = propWait.GetInt32();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to parse existing appsettings.json: {ex.Message}. Using defaults.");
            }
        }

        Console.Write($"Enter Server URL [{serverUrl}]: ");
        string? input = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(input)) serverUrl = input.Trim();

        Console.Write($"Enter Machine ID [{machineId}]: ");
        input = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(input)) machineId = input.Trim();

        Console.Write($"Enter Poll Interval in Seconds [{pollIntervalSeconds}]: ");
        input = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(input) && int.TryParse(input, out int parsedInterval)) pollIntervalSeconds = parsedInterval;

        Console.Write($"Enter Key Storage Path [{keyStoragePath}]: ");
        input = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(input)) keyStoragePath = input.Trim();

        // Write configuration
        try
        {
            var configData = new
            {
                Logging = new
                {
                    LogLevel = new
                    {
                        Default = "Information",
                        Microsoft_Hosting_Lifetime = "Information"
                    }
                },
                RemotePulse = new
                {
                    ServerUrl = serverUrl,
                    MachineId = machineId,
                    KeyStoragePath = keyStoragePath,
                    PollIntervalSeconds = pollIntervalSeconds,
                    LongPollWaitSeconds = longPollWaitSeconds
                }
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            string newJson = JsonSerializer.Serialize(configData, options);
            
            // Normalize "Microsoft_Hosting_Lifetime" back to "Microsoft.Hosting.Lifetime" in appsettings.json
            newJson = newJson.Replace("Microsoft_Hosting_Lifetime", "Microsoft.Hosting.Lifetime");

            File.WriteAllText(configPath, newJson);
            Console.WriteLine("Configuration saved successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving configuration: {ex.Message}");
        }
    }
}

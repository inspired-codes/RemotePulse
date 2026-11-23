using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using InspiredCodes.RemotePulse.App;
using InspiredCodes.RemotePulse.App.Services;
using Microsoft.JSInterop;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddScoped<LocalStorageService>();
builder.Services.AddScoped<CryptoService>();
builder.Services.AddScoped<AppState>();
builder.Services.AddScoped<HubApiClient>();
builder.Services.AddScoped(sp => new ClientWatchdog(
    sp.GetRequiredService<HttpClient>(),
    sp.GetRequiredService<AppState>(),
    sp.GetRequiredService<CryptoService>(),
    sp.GetRequiredService<IJSRuntime>()));

await builder.Build().RunAsync();

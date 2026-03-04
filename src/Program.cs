global using System.Text;
global using System.IdentityModel.Tokens.Jwt;
global using Nager.PublicSuffix.RuleProviders;
global using Nager.PublicSuffix;
using Garde;

var rules = new LocalFileRuleProvider("public_suffix_list.dat");
await rules.BuildAsync();

var auths = new AggregateAuthenticator();

var builder = WebApplication.CreateSlimBuilder(args);
var config = builder.Configuration
            .GetSection(Config.Section)
            .Get<Config>() ?? new();

builder.Services.AddSingleton(config);
builder.Services.AddSingleton(new DomainParser(rules));

builder.Services.AddHttpLogging();
builder.Services.AddSingleton<SecurityHandler>();
builder.Services.AddSingleton<IAuthenticator>(auths);
builder.Services.AddSingleton<IAggregateAuthenticator>(auths);
builder.Configuration.AddEnvironmentVariables();
builder.Logging.AddConsole();

builder.WebHost.UseUrls($"http://*:{config.Port}");

if (config.LogRequests)
{
    builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", LogLevel.Information);
}
else
{
    builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", LogLevel.Warning);
}

var app = builder.Build();
app.UseHttpLogging();
app.UseHtpassword();

Requests.Init(app);

if (auths.Count == 0)
{
    app.Logger.LogWarning("No authenticators registered. All authentication attempts will fail.");
}

app.Run();
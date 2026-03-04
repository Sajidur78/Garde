global using System.Text;
global using System.IdentityModel.Tokens.Jwt;
global using Nager.PublicSuffix.RuleProviders;
global using Nager.PublicSuffix;
using Microsoft.IdentityModel.Tokens;
using System.Buffers.Text;
using Garde;

var rules = new LocalFileRuleProvider("public_suffix_list.dat");
await rules.BuildAsync();

var auths = new AggregateAuthenticator();

var builder = WebApplication.CreateSlimBuilder(args);
var config = builder.Configuration
            .GetSection(Config.Section)
            .Get<Config>() ?? new();

var securityConfig = new SecurityConfig();

builder.Services.AddSingleton(config);
builder.Services.AddSingleton(new DomainParser(rules));

builder.Services.AddHttpLogging();
builder.Services.AddSingleton(securityConfig);
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

var keysPath = Path.Combine(Config.DataPath, ".keys");
var hmacKeysPath = Path.Combine(keysPath, "hs256.key");
Directory.CreateDirectory(keysPath);

if (!File.Exists(hmacKeysPath))
{
    app.Logger.LogInformation("No HMAC key found. Generating a new key.");
    var key = SecurityHandler.GenerateRandomKey();
    File.WriteAllText(hmacKeysPath, Base64Url.EncodeToString(key.Key));

    securityConfig.SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
}
else
{
    try
    {
        var keyBytes = Base64Url.DecodeFromChars(File.ReadAllText(hmacKeysPath));
        var key = new SymmetricSecurityKey(keyBytes);
        securityConfig.SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Failed to load HMAC key from file. Generating a new key.");
    }

    var secureKey = SecurityHandler.GenerateRandomKey();
    File.WriteAllText(hmacKeysPath, Base64Url.EncodeToString(secureKey.Key));

    securityConfig.SigningCredentials = new SigningCredentials(secureKey, SecurityAlgorithms.HmacSha256);
}

app.UseHttpLogging();
app.UseHtpassword(Path.Combine(Config.DataPath, ".htpasswd"));

Requests.Init(app);

if (auths.Count == 0)
{
    app.Logger.LogWarning("No authenticators registered. All authentication attempts will fail.");
}

app.Run();
global using System.Text;
global using System.IdentityModel.Tokens.Jwt;
global using Nager.PublicSuffix.RuleProviders;
global using Nager.PublicSuffix;
using Microsoft.IdentityModel.Tokens;
using System.Buffers.Text;
using Garde;
using System.Security.Cryptography;

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

var keysPath = Path.Combine(Config.PrivateDataPath, ".keys");
var hmacKeysPath = Path.Combine(keysPath, "hs256.key");
var ecdsaKeysPath = Path.Combine(keysPath, "ecdsa");

Directory.CreateDirectory(keysPath);

var keysLoaded = false;
if (File.Exists(ecdsaKeysPath))
{
    try
    {
        var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText($"{ecdsaKeysPath}.pub"));

        // Private key has to be imported after the public key
        key.ImportFromPem(File.ReadAllText(ecdsaKeysPath));

        securityConfig.SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256);
        keysLoaded = true;

        app.Logger.LogInformation("Loaded ECDSA key.");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Failed to load ECDSA key from file. Falling back to HMAC.");
    }
}
else if (File.Exists(hmacKeysPath))
{
    try
    {
        var keyBytes = Base64Url.DecodeFromChars(File.ReadAllText(hmacKeysPath));
        var key = new SymmetricSecurityKey(keyBytes);
        securityConfig.SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        keysLoaded = true;

        app.Logger.LogInformation("Loaded HMAC key.");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Failed to load HMAC key from file. Generating a new key.");
    }
}

if (!keysLoaded)
{
    app.Logger.LogWarning("No valid keys found. Generating new ECDSA key pair.");
    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    
    File.WriteAllText(ecdsaKeysPath, ecdsa.ExportPkcs8PrivateKeyPem());
    File.WriteAllText($"{ecdsaKeysPath}.pub", ecdsa.ExportSubjectPublicKeyInfoPem());
    securityConfig.SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256);
}

app.UseHttpLogging();
app.UseHtpassword(Path.Combine(Config.DataPath, ".htpasswd"));

Requests.Init(app);

if (auths.Count == 0)
{
    app.Logger.LogWarning("No authenticators registered. All authentication attempts will fail.");
}

app.Run();
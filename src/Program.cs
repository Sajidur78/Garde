global using System.Text;
global using System.IdentityModel.Tokens.Jwt;
global using Nager.PublicSuffix.RuleProviders;
global using Nager.PublicSuffix;
using Microsoft.IdentityModel.Tokens;
using System.Buffers.Text;
using Garde;
using System.Security.Cryptography;
using System.Text.Json.Serialization.Metadata;
using System.Text.Json.Serialization;
using ScottBrady.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using ScottBrady.IdentityModel.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

var rules = new LocalFileRuleProvider("public_suffix_list.dat");
await rules.BuildAsync();

var auths = new AggregateAuthenticator();

var builder = WebApplication.CreateSlimBuilder(args);
var config = builder.Configuration
            .GetSection(Config.Section)
            .Get<Config>() ?? new();

var securityConfig = new SecurityConfig();

builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.TypeInfoResolverChain.Add(JsonSerializerTypeInfo.Default);
});

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
var eddsaKeysPath = Path.Combine(keysPath, "eddsa");

Directory.CreateDirectory(keysPath);

var keysLoaded = false;

// Key rotation is a future me problem
if (File.Exists(eddsaKeysPath))
{
    try
    {
        var pubKey = (Ed25519PublicKeyParameters)Extensions.ImportPem(File.ReadAllText($"{eddsaKeysPath}.pub"));
        var privKey = (Ed25519PrivateKeyParameters)Extensions.ImportPem(File.ReadAllText(eddsaKeysPath));

        var eddsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519)
        {
            X = pubKey.GetEncoded(),
            D = privKey.GetEncoded()
        });

        securityConfig.Configure(new EdDsaSecurityKey(eddsa));
        keysLoaded = true;
        app.Logger.LogInformation("Loaded EdDSA keys");
    }
    catch(Exception ex)
    {
        app.Logger.LogInformation(ex, "Failed to load EdDSA key from file. Falling back to ECDSA.");
    }
}
else if (File.Exists(ecdsaKeysPath))
{
    try
    {
        var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText($"{ecdsaKeysPath}.pub"));

        // Private key has to be imported after the public key
        key.ImportFromPem(File.ReadAllText(ecdsaKeysPath));
        
        securityConfig.Configure(new ECDsaSecurityKey(key));
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

        securityConfig.Configure(key, SecurityAlgorithms.HmacSha256);
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
    app.Logger.LogWarning("No valid keys found. Generating new EdDSA key pair.");

    var generator = new Ed25519KeyPairGenerator();
    generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));

    var keys = generator.GenerateKeyPair();
    var pubKey = (Ed25519PublicKeyParameters)keys.Public;
    var privKey = (Ed25519PrivateKeyParameters)keys.Private;

    File.WriteAllText(eddsaKeysPath, privKey.ExportPem());
    File.WriteAllText($"{eddsaKeysPath}.pub", pubKey.ExportPem());

    var eddsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { X = pubKey.GetEncoded(), D = privKey.GetEncoded() });
    securityConfig.Configure(new EdDsaSecurityKey(eddsa));
}

app.UseHttpLogging();
app.UseHtpassword(Path.Combine(Config.DataPath, ".htpasswd"));

Requests.Init(app);

if (auths.Count == 0)
{
    app.Logger.LogWarning("No authenticators registered. All authentication attempts will fail.");
}

app.Run();


[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault | JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(JsonWebKeySet))]
[JsonSerializable(typeof(string))]
public partial class JsonSerializerTypeInfo : JsonSerializerContext
{

}
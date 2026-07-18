namespace Garde;
using Microsoft.IdentityModel.Tokens;
using ScottBrady.IdentityModel;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;
using System.Security.Cryptography;

public class Config
{
    public const string Section = "Garde";
    public static readonly string DataPath = Environment.OSVersion.Platform == PlatformID.Win32NT
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Garde")
        : (Environment.IsPrivilegedProcess 
            ? "/etc/garde" // Use /etc/garde for privileged processes on Unix-like systems otherwise use the user's home directory
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".garde"));

    public static readonly string PrivateDataPath = Environment.OSVersion.Platform == PlatformID.Win32NT
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Garde", ".private")
        : (Environment.IsPrivilegedProcess
            ? "/var/lib/garde" // Use /var/lib/garde for privileged processes on Unix-like systems otherwise use the user's home directory
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".garde", ".private"));

    public bool LogRequests { get; set; } = false;
    public int Port { get; set; } = 5000;
    public string Domain { get; set; } = string.Empty;
    public string Cookie { get; set; } = Requests.DefaultCookieName;
    public long TokenExpiry { get; set; } = 31536000; // Default to 1 year
    public bool ValidateUsers { get; set; } = true;
    public string Issuer { get; set; } = "Garde";
    public ResponseConfig Response { get; set; } = new();

    public class ResponseConfig
    {
        public string UserID { get; set; } = Requests.DefaultUsernameResponseHeader;
    }
}

public class SecurityConfig
{
    public SigningCredentials SigningCredentials { get; internal set; } = SecurityHandler.DefaultCredentials;
    public JsonWebKeySet Jwks { get; internal set; } = new();

    public void Configure(EdDsaSecurityKey key)
    {
        SigningCredentials = new(key, ExtendedSecurityAlgorithms.EdDsa);
        Jwks.Keys.Clear();

        var jwk = ExtendedJsonWebKeyConverter.ConvertFromEdDsaSecurityKey(key);
        jwk.KeyId = key.KeyId;
        jwk.Use = JsonWebKeyUseNames.Sig;
        jwk.D = null; // Remove private key

        Jwks.Keys.Add(jwk);
    }

    public void Configure(RsaSecurityKey key)
    {
        SigningCredentials = new(key, SecurityAlgorithms.RsaSha256);

        Jwks.Keys.Clear();

        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.KeyId = key.KeyId;
        jwk.Use = JsonWebKeyUseNames.Sig;
        jwk.D = null; // Remove private key

        Jwks.Keys.Add(jwk);
    }

    public void Configure(ECDsaSecurityKey key)
    {
        SigningCredentials = new(key, SecurityAlgorithms.EcdsaSha256);

        Jwks.Keys.Clear();

        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.KeyId = key.KeyId;
        jwk.Use = JsonWebKeyUseNames.Sig;
        jwk.D = null; // Remove private key

        Jwks.Keys.Add(jwk);
    }

    /// <summary>
    /// WARN: Symmetric keys don't export jwks
    /// </summary>
    /// <param name="key"></param>
    public void Configure(SymmetricSecurityKey key, string alg)
    {
        SigningCredentials = new(key, alg);
        Jwks.Keys.Clear();
    }
}
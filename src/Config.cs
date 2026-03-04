namespace Garde;
using Microsoft.IdentityModel.Tokens;

public class Config
{
    public const string Section = "Garde";
    public static readonly string DataPath = Environment.OSVersion.Platform == PlatformID.Win32NT
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Garde")
        : (Environment.IsPrivilegedProcess 
            ? "/etc/garde" // Use /etc/garde for privileged processes on Unix-like systems otherwise use the user's home directory
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".garde"));

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
}
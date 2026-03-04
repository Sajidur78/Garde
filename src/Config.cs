namespace Garde;

public class Config
{
    public const string Section = "Garde";

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
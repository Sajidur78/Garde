namespace Garde;
using BCrypt.Net;

public class HtPassword : IAuthenticator
{
    public Dictionary<string, HtPasswordEntry> Entries { get; set; } = new();
    public string Name => "htpasswd";

    public ILogger<HtPassword> Logger { get; init; } = null!;

    public HtPassword()
    {
        var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        Logger = loggerFactory.CreateLogger<HtPassword>();
    }

    public HtPassword(ILogger<HtPassword> logger)
    {
        Logger = logger;
    }

    public bool HasUser(string username)
    {
        return Entries.ContainsKey(username);
    }

    public bool Authenticate(string username, string password)
    {
        if (!Entries.TryGetValue(username, out var entry))
        {
            return false;
        }

        if (entry.Type == HashType.Plain)
        {
            return password == entry.Password;
        }
        else if(entry.Type == HashType.BCrypt)
        {
            return BCrypt.Verify(password, entry.Password);
        }
        else
        {
            Logger.LogWarning("Unsupported hash type {HashType} for user {Username}", entry.Type, entry.Username);
        }

        return false;
    }

    public static HtPassword FromFile(string path)
    {
        var htPassword = new HtPassword();
        if (!File.Exists(path)) 
        {
            return htPassword;
        }

        htPassword.ReadFile(path);
        return htPassword;
    }

    public static HtPassword FromString(string text)
    {
        var htPassword = new HtPassword();
        htPassword.ReadString(text);
        return htPassword;
    }

    public void ReadFile(string path)
    {
        ReadString(File.ReadAllText(path));
    }

    public void ReadString(string text)
    {
        var lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

        foreach (var line in lines)
        {
            var entry = ParseLine(line);
            if (entry != null)
            {
                Entries[entry.Username] = entry;
            }
        }
    }

    public static HtPasswordEntry? ParseLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.FirstOrDefault(x => !char.IsWhiteSpace(x)) == '#')
        {
            return null;
        }

        var parts = line.Split(':', 2);
        if (parts.Length == 2)
        {
            var type = HashType.Plain;
            var passwordPart = parts[1];

            const string bcryptTemplate = "$2.$";
            if (passwordPart.Length > bcryptTemplate.Length && 
                (passwordPart[0] == bcryptTemplate[0] && passwordPart[1] == bcryptTemplate[1]
                && passwordPart[3] == bcryptTemplate[3]))
            {
                type = HashType.BCrypt;
            }
            else if (passwordPart.StartsWith("$apr1$"))
            {
                type = HashType.MD5;
                passwordPart = passwordPart.Substring("$apr1$".Length);
            }
            else if (passwordPart.StartsWith("{SHA256}"))
            {
                type = HashType.SHA256;
                passwordPart = passwordPart.Substring("{SHA256}".Length);
            }
            else if (passwordPart.StartsWith("{SHA512}"))
            {
                type = HashType.SHA512;
                passwordPart = passwordPart.Substring("{SHA512}".Length);
            }

            return new HtPasswordEntry(parts[0], passwordPart, type);
        }

        return null;
    }

    public enum HashType
    {
        Plain,
        BCrypt,
        MD5,
        SHA256,
        SHA512
    }
}

public record class HtPasswordEntry(string Username, string Password, HtPassword.HashType Type);

public static class HtPasswordExtensions
{
    public static void UseHtpassword(this IApplicationBuilder app, string path = ".htpasswd")
    {
        var auths = app.ApplicationServices.GetRequiredService<IAggregateAuthenticator>() as AggregateAuthenticator;
        if (auths == null) 
        {
            throw new NotSupportedException("AggregateAuthenticator is not registered in the service collection.");
        }

        if (File.Exists(path))
        {
            var logger = app.ApplicationServices.GetRequiredService<ILogger<HtPassword>>();
            var htPassword = new HtPassword(logger);

            htPassword.Logger.LogInformation("Found .htpasswd, loading .htpasswd file");
            
            htPassword.ReadFile(path);

            htPassword.Logger.LogInformation("Loaded {Count} entries from .htpasswd file", htPassword.Entries.Count);
            
            auths.Add(htPassword);
        }
    }
}
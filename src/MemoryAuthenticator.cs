namespace Garde;

public class MemoryAuthenticator : IAuthenticator
{
    public string Name => "Memory";
    private readonly Dictionary<string, string> Users = new();

    public bool HasUser(string username) => Users.ContainsKey(username);

    public void AddUser(string username, string password)
    {
        Users[username] = password;
    }

    public bool Authenticate(string username, string password)
    {
        return Users.TryGetValue(username, out var storedPassword) && storedPassword == password;
    }
}
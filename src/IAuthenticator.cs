namespace Garde;

public interface IAuthenticator
{
    public string Name { get; }

    bool HasUser(string username);
    /// <summary>
    /// Authorizes a user based on the provided credentials.
    /// </summary>
    /// <param name="username">The username of the user to authorize.</param>
    /// <param name="password">The password of the user to authorize.</param>
    /// <returns>True if the user is authorized; otherwise, false.</returns>
    bool Authenticate(string username, string password);
}

public interface IAggregateAuthenticator : IAuthenticator
{
    bool HasUser(string username, out IAuthenticator? authenticator);

    bool Authenticate(string username, string password, out IAuthenticator? authenticator);
}
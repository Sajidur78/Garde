namespace Garde;

using Microsoft.AspNetCore.Server.IIS;
using System.Collections;

public class AggregateAuthenticator : IAggregateAuthenticator, IList<IAuthenticator>
{
    public string Name => "Aggregate";
    public List<IAuthenticator> Authenticators { get; } = new();

    public int Count => Authenticators.Count;

    public bool IsReadOnly => false;
    public IAuthenticator this[int index] { get => ((IList<IAuthenticator>)Authenticators)[index]; set => ((IList<IAuthenticator>)Authenticators)[index] = value; }

    public bool HasUser(string username, out IAuthenticator? validatedAuth)
    {
        validatedAuth = null;
        foreach (IAuthenticator authenticator in Authenticators)
        {
            if (authenticator.HasUser(username))
            {
                validatedAuth = authenticator;
                return true;
            }
        }

        return false;
    }

    public bool HasUser(string username)
    {
        return HasUser(username, out _);
    }

    public bool Authenticate(string username, string password, out IAuthenticator? validatedAuth)
    {
        validatedAuth = null;

        foreach (var authenticator in Authenticators) 
        {
            if (authenticator.Authenticate(username, password))
            {
                validatedAuth = authenticator;
                return true;
            }
        }

        return false;
    }

    public bool Authenticate(string username, string password)
    {
        return Authenticate(username, password, out _);
    }

    public void Add(IAuthenticator item)
    {
        Authenticators.Add(item);
    }

    public void Clear()
    {
        Authenticators.Clear();
    }

    public bool Contains(IAuthenticator item)
    {
        return Authenticators.Contains(item);
    }

    public void CopyTo(IAuthenticator[] array, int arrayIndex)
    {
        Authenticators.CopyTo(array, arrayIndex);
    }

    public IEnumerator<IAuthenticator> GetEnumerator()
    {
        return Authenticators.GetEnumerator();
    }

    public int IndexOf(IAuthenticator item)
    {
        return Authenticators.IndexOf(item);
    }

    public void Insert(int index, IAuthenticator item)
    {
        Authenticators.Insert(index, item);
    }

    public bool Remove(IAuthenticator item)
    {
        return Authenticators.Remove(item);
    }

    public void RemoveAt(int index)
    {
        Authenticators.RemoveAt(index);
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable)Authenticators).GetEnumerator();
    }
}
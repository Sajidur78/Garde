namespace Garde.WellKnown;
using Microsoft.IdentityModel.Tokens;

public static class JsonWebKeys
{
    public static JsonWebKeySet Get(SecurityConfig security)
    {
        return security.Jwks;
    }
}
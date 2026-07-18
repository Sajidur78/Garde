namespace Garde.WellKnown;

public class OpenId
{
    public static OpenIdConfig Get(Config config)
    {
        return new OpenIdConfig
        {
            Issuer = config.Issuer,
            JwksUri = $"{config.Issuer}/.well-known/jwks.json"
        };
    }
}
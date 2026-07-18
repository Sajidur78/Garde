namespace Garde;
using System.Text.Json.Serialization;

public struct OpenIdConfig
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = "Garde";

    // public string AuthorizationEndpoint { get; set; } = "/authorize";
    // public string TokenEndpoint { get; set; } = "/token";
    // public string UserInfoEndpoint { get; set; } = "/userinfo";

    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; set; } = "/.well-known/jwks.json";

    public OpenIdConfig()
    {
    }
}
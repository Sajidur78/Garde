namespace Garde;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

public class SecurityHandler
{
    public static readonly SecurityKey DefaultKey = new SymmetricSecurityKey(SHA256.HashData("very_secret"u8));
    public static readonly SigningCredentials DefaultCredentials = new(DefaultKey, SecurityAlgorithms.HmacSha256);
    
    public SigningCredentials Credentials { get; init; } = DefaultCredentials;
    public JwtSecurityTokenHandler TokenHandler { get; } = new();
    public Config Configuration { get; }

    public string AudiencePrefix => $"{Configuration.Issuer}/";
    public string SourcePrefix => $"{Configuration.Issuer}/";

    public SecurityHandler(Config config) 
    {
        Configuration = config;
    }

    public string IssueToken(string name, string aud, string source, DateTime expiry)
    {
        return IssueToken(aud, source, expiry, [
            new Claim(JwtRegisteredClaimNames.Name, name)
        ]);
    }

    public string IssueToken(string aud, string source, DateTime expiry, IEnumerable<Claim>? claims = null)
    {
        var issuedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var token = new JwtSecurityToken(
            issuer: Configuration.Issuer,
            expires: expiry,
            claims: [
                ..(claims ?? []),
                new (JwtRegisteredClaimNames.Iat, issuedTime),
                new (JwtRegisteredClaimNames.Nbf, issuedTime),
                new (JwtRegisteredClaimNames.Aud, $"{AudiencePrefix}{aud}"),
                new ("src", $"{SourcePrefix}{source}")
            ],
            signingCredentials: Credentials
        );

        return TokenHandler.WriteToken(token);
    }

    public JwtSecurityToken ValidateToken(string token, string? aud)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = Configuration.Issuer,
            ValidAudience = string.IsNullOrEmpty(aud) ? string.Empty : $"{AudiencePrefix}{aud}",
            IssuerSigningKey = Credentials.Key,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            RequireExpirationTime = true,
            ValidateAudience = !string.IsNullOrEmpty(aud)
        };

        var principal = TokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
        if (validatedToken is not JwtSecurityToken jwtToken)
        {
            throw new SecurityTokenException("Invalid token");
        }

        return jwtToken;
    }
}
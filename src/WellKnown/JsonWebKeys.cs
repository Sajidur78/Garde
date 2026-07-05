namespace Garde.WellKnown;

public static class JsonWebKeys
{
    public static IResult Get(SecurityConfig security)
    {
        return Results.Json(security.Jwks, JsonSerializerTypeInfo.Default);
    }
}
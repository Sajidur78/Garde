namespace Garde;

public static class Extensions
{
    public static string GetFullPath(this HttpContext ctx)
    {
        return $"{ctx.Request.Path}{ctx.Request.QueryString}";
    }
}
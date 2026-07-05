namespace Garde;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;

public static class Extensions
{
    public static string GetFullPath(this HttpContext ctx)
    {
        return $"{ctx.Request.Path}{ctx.Request.QueryString}";
    }

    public static object ImportPem(this string pem)
    {
        var textReader = new StringReader(pem);
        using var pemReader = new PemReader(textReader);
        return pemReader.ReadObject();
    }

    public static string ExportPem(this AsymmetricKeyParameter parameter)
    {
        var textWriter = new StringWriter();
        using var pemWriter = new PemWriter(textWriter);

        pemWriter.WriteObject(parameter);

        return textWriter.ToString();
    }
}
namespace Garde;

public static class Requests
{
    public const string DefaultCookieName = "Garde-Auth";
    public const string DefaultUsernameResponseHeader = "X-Garde-User";

    public static SecurityHandler Security { get; private set; } = null!;
    public static Config Configuration { get; private set; } = null!;

    public static string AuthCookieDomain => Configuration.Domain;
    public static string AuthCookieName => Configuration.Cookie;

    public static void Init(WebApplication app)
    {
        Security = app.Services.GetRequiredService<SecurityHandler>();
        Configuration = app.Services.GetRequiredService<IConfiguration>()
            .GetSection(Config.Section)
            .Get<Config>() ?? new();

        app.MapGet("/", Login.Get);
        app.MapGet("/login", Login.Get);
        app.MapPost("/login", Login.Post);
        app.MapGet("/auth", Auth.Get);
    }

    public class Auth
    {
        public static string UsernameResoponseHeader => Configuration.Response.UserID;

        public static IResult Get(HttpContext ctx, ILogger<Auth> log, IAggregateAuthenticator auths)
        {
            if (ctx.Request.Cookies.TryGetValue(AuthCookieName, out var authCookie) && !string.IsNullOrEmpty(authCookie))
            {
                JwtSecurityToken token = null!;
                try
                {
                    token = Security.ValidateToken(authCookie, "User");
                }
                catch
                {
                    log.LogWarning("Invalid login token. {IP}, {Path}, {Token}", ctx.Connection.RemoteIpAddress, ctx.GetFullPath(), authCookie);
                    return Results.Unauthorized();
                }

                if (Configuration.ValidateUsers)
                {
                    var username = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Name)?.Value;
                    if (string.IsNullOrEmpty(username) || !auths.HasUser(username))
                    {
                        log.LogWarning("User from token does not exist. {IP}, {Path}, {Username}", ctx.Connection.RemoteIpAddress, ctx.GetFullPath(), username);
                        ctx.Response.Cookies.Delete(AuthCookieName);
                        return Results.Unauthorized();
                    }
                }

                var authUser = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Name)?.Value;
                if (string.IsNullOrEmpty(authUser))
                {
                    log.LogWarning("Token does not contain username. {IP}, {Path}, {Token}", ctx.Connection.RemoteIpAddress, ctx.GetFullPath(), token);
                }

                ctx.Response.Headers.Append(UsernameResoponseHeader, authUser ?? "Unknown");

                return Results.Ok();
            }

            return Results.Unauthorized();
        }
    }

    public class Login
    {
        public static string Get(HttpContext ctx, bool? tokenOnly, string? redirect, string? reason)
        {
            tokenOnly ??= false;
            var csrf = Security.IssueToken(Guid.NewGuid().ToString(), "CSRF", "CSRF", DateTime.UtcNow.AddMinutes(5));
            if (tokenOnly == true)
            {
                return csrf;
            }

            ctx.Response.ContentType = "text/html";

            if (reason == "invalid_credentials")
            {
                reason = "Invalid username or password.";
            }

            var loginPageBuilder = new StringBuilder(Content.Login);
            loginPageBuilder.Replace("{{CSRF_TOKEN}}", csrf);
            loginPageBuilder.Replace("{{REDIRECT_URL}}", redirect ?? string.Empty);
            loginPageBuilder.Replace("{{ERROR_MESSAGE}}", reason ?? string.Empty);

            return loginPageBuilder.ToString();
        }

        public static IResult Post(HttpContext ctx, ILogger<Login> log, IAggregateAuthenticator auth, DomainParser domainParser)
        {
            if (ctx.Request.HasFormContentType == false)
            {
                return Results.BadRequest();
            }

            var csrf = ctx.Request.Form["csrf"];
            if (string.IsNullOrEmpty(csrf))
            {
                log.LogWarning("CSRF Attack detected {IP}, {Path}", ctx.Connection.RemoteIpAddress, ctx.GetFullPath());
                return Results.BadRequest("CSRF Attack detected");
            }
            else
            {
                try
                {
                    Security.ValidateToken(csrf!, "CSRF");
                }
                catch
                {
                    log.LogWarning("CSRF Attack detected {IP}, {Path}, {Token}", ctx.Connection.RemoteIpAddress, ctx.GetFullPath(), csrf);
                    return Results.BadRequest("CSRF Attack detected");
                }
            }

            var username = ctx.Request.Form["username"].ToString();
            var password = ctx.Request.Form["password"].ToString();
            var redirect = ctx.Request.Form["redirect"].ToString();

            if (string.IsNullOrEmpty(username))
            {
                return Unauthorized("invalid_credentials");
            }

            if (!auth.Authenticate(username, password, out var authenticator))
            {
                log.LogWarning("Invalid login attempt. {IP}, {Path}, {Username}", ctx.Connection.RemoteIpAddress, ctx.GetFullPath(), username);
                return Unauthorized("invalid_credentials");
            }

            var token = Security.IssueToken(username!, "User", authenticator!.Name, DateTime.UtcNow.AddSeconds(Configuration.TokenExpiry));

            // Select domain name if no explicit domain is set
            var cookieDomain = string.IsNullOrEmpty(AuthCookieDomain) 
                ? (domainParser.Parse(ctx.Request.Host.Host)?.RegistrableDomain ?? ctx.Request.Host.Host) 
                : AuthCookieDomain;

            ctx.Response.Cookies.Append(AuthCookieName, token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTimeOffset.UtcNow.AddSeconds(Configuration.TokenExpiry),
                Domain = cookieDomain
            });

            if (!string.IsNullOrEmpty(redirect))
            {
                return Results.Redirect(redirect);
            }

            return Results.Ok();

            IResult Unauthorized(string reason)
            {
                var baseRedirect = "/login?reason=" + Uri.EscapeDataString(reason);
                if (string.IsNullOrEmpty(redirect))
                {
                    return Results.Redirect(baseRedirect);
                }

                return Results.Redirect($"{baseRedirect}&redirect={Uri.EscapeDataString(redirect)}");
            }
        }
    }
}
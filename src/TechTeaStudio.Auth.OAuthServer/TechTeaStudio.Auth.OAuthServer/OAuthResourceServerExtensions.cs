using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TechTeaStudio.Auth.Signing;

namespace TechTeaStudio.Auth.OAuthServer;

public static class OAuthResourceServerExtensions
{
    /// <summary>
    /// Registers a JwtBearer scheme for the protected resource (your MCP endpoint) that accepts only the access
    /// tokens this module issues: header <c>typ</c> = <c>at+jwt</c> (RFC 9068), <c>aud</c> equal to
    /// <paramref name="resource"/>, <c>iss</c> equal to <see cref="OAuthServerOptions.Issuer"/>, signature checked
    /// against the library's signing keys (rotation included). A first-party token, which has neither the type nor
    /// that audience, is refused. Use it as the only scheme of the resource endpoints.
    /// </summary>
    public static AuthenticationBuilder AddTechTeaStudioOAuthResourceServer(this AuthenticationBuilder builder, string scheme, string resource)
    {
        if (builder is null) throw new ArgumentNullException(nameof(builder));
        if (string.IsNullOrEmpty(scheme)) throw new ArgumentException("scheme is required.", nameof(scheme));
        if (string.IsNullOrEmpty(resource)) throw new ArgumentException("resource is required.", nameof(resource));

        builder.Services.AddOptions<JwtBearerOptions>(scheme)
            .Configure<IOptionsMonitor<AuthOptions>, IOptionsMonitor<OAuthServerOptions>>((o, auth, oauth) =>
            {
                o.MapInboundClaims = false;
                o.RequireHttpsMetadata = false;
                o.SaveToken = false;

                var p = SigningKeyResolver.BuildValidationParameters(auth.CurrentValue);
                p.ValidateIssuer = true;
                p.ValidIssuer = oauth.CurrentValue.Issuer;
                p.ValidIssuers = null;
                p.ValidateAudience = true;
                p.ValidAudience = resource;
                p.ValidAudiences = null;
                p.ValidTypes = new[] { "at+jwt" };
                p.ValidateLifetime = true;
                p.ValidateIssuerSigningKey = true;
                p.IssuerSigningKeyResolver = (_, _, _, _) =>
                    SigningKeyResolver.ResolveValidating(auth.CurrentValue).Select(SigningKeyResolver.BuildValidationKey);
                o.TokenValidationParameters = p;
            });

        return builder.AddJwtBearer(scheme, _ => { });
    }
}

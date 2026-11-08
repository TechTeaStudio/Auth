using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Internal;
using TechTeaStudio.Auth.OAuthServer.Services;

namespace TechTeaStudio.Auth.OAuthServer;

/// <summary>Maps the authorization server endpoints. Rate limiting and CORS are the host's job; the paths are in <see cref="OAuthServerPaths"/>.</summary>
public static class OAuthServerEndpointExtensions
{
    private const int MaxRegistrationBytes = 16 * 1024;

    /// <summary>
    /// Maps metadata, authorize, token, revoke and (when enabled) register. The returned builder applies conventions
    /// (<c>RequireRateLimiting</c>, <c>RequireCors</c>, ...) to every mapped endpoint.
    /// </summary>
    public static IEndpointConventionBuilder MapTechTeaStudioOAuthServer(this IEndpointRouteBuilder endpoints)
    {
        if (endpoints is null) throw new ArgumentNullException(nameof(endpoints));
        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<OAuthServerOptions>>().Value;

        var mapped = new List<IEndpointConventionBuilder>();

        mapped.Add(endpoints.MapGet(OAuthServerPaths.Metadata, ctx => MetadataAsync(ctx)));
        var issuerPath = Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuerUri) ? issuerUri.AbsolutePath.TrimEnd('/') : string.Empty;
        if (issuerPath.Length > 0)
            mapped.Add(endpoints.MapGet(OAuthServerPaths.Metadata + issuerPath, ctx => MetadataAsync(ctx)));

        mapped.Add(endpoints.MapGet(OAuthServerPaths.Authorize, ctx => AuthorizeAsync(ctx)));
        mapped.Add(endpoints.MapPost(OAuthServerPaths.Token, ctx => TokenAsync(ctx)));
        mapped.Add(endpoints.MapPost(OAuthServerPaths.Revoke, ctx => RevokeAsync(ctx)));
        if (options.EnableDynamicRegistration)
            mapped.Add(endpoints.MapPost(OAuthServerPaths.Register, ctx => RegisterAsync(ctx)));

        return new CompositeConventionBuilder(mapped);
    }

    private static Task MetadataAsync(HttpContext ctx)
    {
        var o = ctx.RequestServices.GetRequiredService<IOptions<OAuthServerOptions>>().Value;
        var methods = new List<string> { "none" };
        if (o.Clients.Any(c => !string.IsNullOrEmpty(c.ClientSecret))) methods.Add("client_secret_post");

        var doc = new Dictionary<string, object?>
        {
            ["issuer"] = o.Issuer,
            ["authorization_endpoint"] = o.EndpointUrl(OAuthServerPaths.Authorize),
            ["token_endpoint"] = o.EndpointUrl(OAuthServerPaths.Token),
            ["revocation_endpoint"] = o.EndpointUrl(OAuthServerPaths.Revoke),
            ["registration_endpoint"] = o.EnableDynamicRegistration ? o.EndpointUrl(OAuthServerPaths.Register) : null,
            ["response_types_supported"] = new[] { "code" },
            ["grant_types_supported"] = new[] { "authorization_code", "refresh_token" },
            ["code_challenge_methods_supported"] = new[] { "S256" },
            ["token_endpoint_auth_methods_supported"] = methods,
            ["revocation_endpoint_auth_methods_supported"] = methods,
            ["scopes_supported"] = o.Scopes.Select(s => s.Name).ToArray(),
            ["client_id_metadata_document_supported"] = o.EnableClientIdMetadataDocuments,
            ["authorization_response_iss_parameter_supported"] = true,
        };
        ctx.Response.Headers["Cache-Control"] = "public, max-age=" + (int)o.MetadataCacheMaxAge.TotalSeconds;
        return WriteJsonAsync(ctx, 200, doc);
    }

    private static async Task AuthorizeAsync(HttpContext ctx)
    {
        var svc = ctx.RequestServices.GetRequiredService<OAuthAuthorizationService>();
        var outcome = await svc.BeginAsync(ctx.Request.Query, ctx.RequestAborted).ConfigureAwait(false);
        NoStore(ctx);
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        if (outcome.Location is not null)
        {
            if (outcome.PendingId is not null)
                ConsentBinding.Add(ctx, outcome.PendingId, ctx.RequestServices.GetRequiredService<IOptions<OAuthServerOptions>>().Value.PendingRequestLifetime);
            ctx.Response.StatusCode = StatusCodes.Status302Found;
            ctx.Response.Headers["Location"] = outcome.Location;
            return;
        }
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        await ctx.Response.WriteAsync(outcome.PlainError ?? "invalid_request", ctx.RequestAborted).ConfigureAwait(false);
    }

    private static async Task TokenAsync(HttpContext ctx)
    {
        NoStore(ctx);
        var form = await ReadFormAsync(ctx).ConfigureAwait(false);
        if (form is null)
        {
            await WriteResultAsync(ctx, TokenEndpointResult.Error("invalid_request", "Body must be application/x-www-form-urlencoded.")).ConfigureAwait(false);
            return;
        }
        var svc = ctx.RequestServices.GetRequiredService<OAuthTokenService>();
        await WriteResultAsync(ctx, await svc.HandleAsync(form, ctx.RequestAborted).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private static async Task RevokeAsync(HttpContext ctx)
    {
        NoStore(ctx);
        var form = await ReadFormAsync(ctx).ConfigureAwait(false);
        if (form is null || form["token"].ToString().Length == 0)
        {
            await WriteResultAsync(ctx, TokenEndpointResult.Error("invalid_request", "token is required.")).ConfigureAwait(false);
            return;
        }
        var result = await ctx.RequestServices.GetRequiredService<OAuthTokenService>().RevokeAsync(form, ctx.RequestAborted).ConfigureAwait(false);
        if (result.Status == StatusCodes.Status200OK) ctx.Response.StatusCode = StatusCodes.Status200OK;
        else await WriteResultAsync(ctx, result).ConfigureAwait(false);
    }

    private static async Task RegisterAsync(HttpContext ctx)
    {
        NoStore(ctx);
        if (ctx.Request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) != true)
        {
            await WriteResultAsync(ctx, TokenEndpointResult.Error("invalid_client_metadata", "Body must be application/json.")).ConfigureAwait(false);
            return;
        }

        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await ctx.Request.Body.ReadAsync(chunk.AsMemory(), ctx.RequestAborted).ConfigureAwait(false)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > MaxRegistrationBytes)
            {
                await WriteResultAsync(ctx, TokenEndpointResult.Error("invalid_client_metadata", "Body is too large.")).ConfigureAwait(false);
                return;
            }
        }

        JsonDocument doc;
        try { doc = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 8 }); }
        catch (JsonException)
        {
            await WriteResultAsync(ctx, TokenEndpointResult.Error("invalid_client_metadata", "Body is not valid JSON.")).ConfigureAwait(false);
            return;
        }

        using (doc)
        {
            var svc = ctx.RequestServices.GetRequiredService<OAuthRegistrationService>();
            await WriteResultAsync(ctx, await svc.RegisterAsync(doc.RootElement, ctx.RequestAborted).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }

    private static async Task<IFormCollection?> ReadFormAsync(HttpContext ctx)
    {
        if (ctx.Request.ContentType?.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) != true) return null;
        try { return await ctx.Request.ReadFormAsync(ctx.RequestAborted).ConfigureAwait(false); }
        catch (InvalidDataException) { return null; }
    }

    private static void NoStore(HttpContext ctx)
    {
        ctx.Response.Headers["Cache-Control"] = "no-store";
        ctx.Response.Headers["Pragma"] = "no-cache";
    }

    private static Task WriteResultAsync(HttpContext ctx, TokenEndpointResult result) => WriteJsonAsync(ctx, result.Status, result.Body);

    private static async Task WriteJsonAsync(HttpContext ctx, int status, IEnumerable<KeyValuePair<string, object?>> body)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        var dict = new Dictionary<string, object?>();
        foreach (var kv in body)
            if (kv.Value is not null) dict[kv.Key] = kv.Value;
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(dict), ctx.RequestAborted).ConfigureAwait(false);
    }

    private sealed class CompositeConventionBuilder : IEndpointConventionBuilder
    {
        private readonly List<IEndpointConventionBuilder> _inner;
        public CompositeConventionBuilder(List<IEndpointConventionBuilder> inner) => _inner = inner;
        public void Add(Action<EndpointBuilder> convention)
        {
            foreach (var b in _inner) b.Add(convention);
        }
    }
}

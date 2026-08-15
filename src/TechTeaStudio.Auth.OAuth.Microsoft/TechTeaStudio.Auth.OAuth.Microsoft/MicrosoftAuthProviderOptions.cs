namespace TechTeaStudio.Auth.OAuth.Microsoft;

/// <summary>
/// Options for <see cref="MicrosoftAuthProvider"/>, bound from <c>Auth:Microsoft</c> by default.
/// </summary>
public sealed class MicrosoftAuthProviderOptions
{
    /// <summary>Application (client) ID from the Entra app registration. Also the audience every
    /// id_token is validated against.</summary>
    public string? ClientId { get; set; }

    /// <summary>Client secret from the same app registration. The provider runs the confidential
    /// authorization-code flow, so this is required.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Tenant segment of the authority. <c>common</c> (work, school and personal
    /// accounts), <c>organizations</c>, <c>consumers</c>, or a tenant GUID for single-tenant apps.
    /// A GUID here is enforced: an id_token from any other tenant is rejected.</summary>
    public string TenantId { get; set; } = "common";

    /// <summary>The redirect URI the authorize request used. Entra requires it again on the token
    /// exchange and rejects the call when the two differ, so it cannot be inferred here. Must be
    /// one of the URIs registered on the app.</summary>
    public string? RedirectUri { get; set; }

    /// <summary>Scopes sent on the token exchange. <c>openid</c> is what produces an id_token at
    /// all; <c>email</c> and <c>profile</c> fill the address and display name.</summary>
    public string Scope { get; set; } = "openid email profile";

    /// <summary>Authority host. Sovereign clouds override it (e.g.
    /// <c>https://login.microsoftonline.us</c>).</summary>
    public string Instance { get; set; } = "https://login.microsoftonline.com";

    /// <summary>How long a fetched JWKS document is reused before being re-fetched. A signature
    /// that fails on an unknown key id forces a refresh regardless, so this only bounds how long a
    /// retired key stays cached.</summary>
    public TimeSpan SigningKeyCacheLifetime { get; set; } = TimeSpan.FromHours(12);

    /// <summary>When true, a token carrying no usable address is rejected instead of being
    /// surfaced with a null <see cref="ExternalLoginInfo.Email"/>. Off by default: the consumer's
    /// <c>IExternalUserBridge</c> decides what an address-less account means.</summary>
    public bool RequireEmail { get; set; }

    /// <summary>Allowed clock skew when validating <c>nbf</c> / <c>exp</c>.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);
}

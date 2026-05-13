using Microsoft.AspNetCore.Authentication;

namespace TechTeaStudio.Auth.AspNetCore.ApiKey;

public sealed class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>Default header name when no override is supplied. Stable string contract.</summary>
    public const string DefaultHeader = "X-Api-Key";

    /// <summary>Header to read the key from. Default: <c>X-Api-Key</c>.</summary>
    public string HeaderName { get; set; } = DefaultHeader;

    /// <summary>
    /// When true (default), the handler also accepts <c>Authorization: ApiKey &lt;key&gt;</c>.
    /// Set to false to require <see cref="HeaderName"/> exclusively.
    /// </summary>
    public bool AllowAuthorizationHeader { get; set; } = true;
}

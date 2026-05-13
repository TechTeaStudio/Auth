namespace TechTeaStudio.Auth.Signing;

/// <summary>
/// Nested signing-key configuration on <see cref="JwtOptions"/>. When
/// <see cref="Keys"/> is empty, the library synthesizes a single HS256 descriptor
/// from <see cref="JwtOptions.SecretKey"/> with <c>kid = "default"</c> for backward compatibility.
/// </summary>
public sealed class SigningOptions
{
    /// <summary>
    /// All signing keys known to this service. Tokens are signed by the entry whose
    /// <see cref="SigningKeyDescriptor.Kid"/> matches <see cref="ActiveKid"/>; tokens
    /// are validated by any entry within the retention window.
    /// </summary>
    public IList<SigningKeyDescriptor> Keys { get; set; } = new List<SigningKeyDescriptor>();

    /// <summary>
    /// <c>kid</c> used for signing new tokens. <c>null</c> selects the first entry
    /// in <see cref="Keys"/>, or "default" when the legacy <see cref="JwtOptions.SecretKey"/>
    /// is in effect.
    /// </summary>
    public string? ActiveKid { get; set; }

    /// <summary>
    /// Window during which a retired key still validates incoming tokens. Default: 7 days.
    /// Set to <see cref="TimeSpan.Zero"/> to validate against the active key only.
    /// </summary>
    public TimeSpan KeyRetention { get; set; } = TimeSpan.FromDays(7);
}

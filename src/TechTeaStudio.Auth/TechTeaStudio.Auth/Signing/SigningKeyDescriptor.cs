namespace TechTeaStudio.Auth.Signing;

/// <summary>
/// One entry in the signing-key set. Only the field appropriate to
/// <see cref="Algorithm"/> needs to be populated:
/// <list type="bullet">
///   <item><see cref="SigningAlgorithm.HS256"/> — <see cref="SymmetricKey"/> (≥ 32 UTF-8 bytes).</item>
///   <item><see cref="SigningAlgorithm.RS256"/> / <see cref="SigningAlgorithm.ES256"/> —
///     <see cref="PrivateKeyPem"/> for signing, <see cref="PublicKeyPem"/> for validation-only nodes.</item>
/// </list>
/// </summary>
public sealed class SigningKeyDescriptor
{
    /// <summary>Stable key identifier written into the JWT <c>kid</c> header.</summary>
    public string Kid { get; set; } = "default";

    /// <summary>Algorithm this key signs / validates with.</summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.HS256;

    /// <summary>UTC timestamp the key was minted. Used by the retention window.</summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Symmetric key material (HS256 only). ≥ 32 UTF-8 bytes.</summary>
    public string? SymmetricKey { get; set; }

    /// <summary>PEM-encoded PKCS#8 private key (RS256 / ES256). Used to sign new tokens.</summary>
    public string? PrivateKeyPem { get; set; }

    /// <summary>PEM-encoded SubjectPublicKeyInfo public key (RS256 / ES256). Used for validation when no private key is available.</summary>
    public string? PublicKeyPem { get; set; }
}

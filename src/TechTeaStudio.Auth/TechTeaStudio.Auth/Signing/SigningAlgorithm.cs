namespace TechTeaStudio.Auth.Signing;

/// <summary>Signing algorithms supported by <see cref="SigningKeyDescriptor"/>.</summary>
public enum SigningAlgorithm
{
    /// <summary>Symmetric HMAC-SHA256. Default. Same key on both sides.</summary>
    HS256 = 0,

    /// <summary>Asymmetric RSA-SHA256. Private key signs; public key validates / publishes via JWKS.</summary>
    RS256 = 1,

    /// <summary>Asymmetric ECDSA P-256 SHA-256.</summary>
    ES256 = 2,
}

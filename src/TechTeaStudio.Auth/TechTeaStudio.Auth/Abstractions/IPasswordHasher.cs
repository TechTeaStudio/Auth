namespace TechTeaStudio.Auth.Abstractions;

/// <summary>
/// Hashes and verifies user passwords. Implementations must use a cryptographically
/// strong, salted, slow KDF (e.g. PBKDF2-SHA256) and embed all parameters in the hash string.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes <paramref name="password"/> with a fresh per-call salt and returns an
    /// opaque string that contains the algorithm, parameters, salt, and digest.
    /// The returned value is safe to store in a database column and to pass back to
    /// <see cref="Verify"/> later.
    /// </summary>
    string Hash(string password);

    /// <summary>
    /// Verifies that <paramref name="providedPassword"/> matches the previously
    /// produced <paramref name="hashedPassword"/>. Comparison MUST run in constant
    /// time relative to the digest length to avoid timing side-channels.
    /// </summary>
    /// <returns><c>true</c> when the password matches; otherwise <c>false</c>.</returns>
    bool Verify(string hashedPassword, string providedPassword);
}

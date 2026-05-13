using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Signing;

namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// Validates <see cref="AuthOptions"/> across nested sections: signing keys
/// (either <c>Jwt.SecretKey</c> or at least one descriptor in <c>Jwt.Signing.Keys</c>),
/// sane lifetimes, and the relationship between access-token and refresh-token TTLs.
/// </summary>
public sealed class AuthOptionsValidator : IValidateOptions<AuthOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthOptions options)
    {
        if (options is null) return ValidateOptionsResult.Fail("AuthOptions is null.");

        var failures = new List<string>();

        ValidateAnnotated(options.Jwt, "Jwt", failures);
        ValidateAnnotated(options.Lockout, "Lockout", failures);

        // Jwt signing key: either Signing.Keys has entries, or SecretKey is set.
        if (options.Jwt.Signing.Keys.Count == 0)
        {
            if (string.IsNullOrEmpty(options.Jwt.SecretKey))
                failures.Add("Auth:Jwt:SecretKey is required when Auth:Jwt:Signing:Keys is empty.");
            else if (Encoding.UTF8.GetByteCount(options.Jwt.SecretKey) < 32)
                failures.Add("Auth:Jwt:SecretKey must be at least 32 bytes (256 bits) when UTF-8-encoded.");
        }
        else
        {
            foreach (var k in options.Jwt.Signing.Keys)
            {
                if (string.IsNullOrEmpty(k.Kid))
                {
                    failures.Add("Auth:Jwt:Signing:Keys[*]:Kid is required.");
                    continue;
                }
                try { _ = SigningKeyResolver.BuildValidationKey(k); }
                catch (Exception ex) { failures.Add($"Auth:Jwt:Signing:Keys['{k.Kid}']: {ex.Message}"); }
            }

            if (!string.IsNullOrEmpty(options.Jwt.Signing.ActiveKid)
                && !options.Jwt.Signing.Keys.Any(k => k.Kid == options.Jwt.Signing.ActiveKid))
            {
                failures.Add($"Auth:Jwt:Signing:ActiveKid '{options.Jwt.Signing.ActiveKid}' is not present in Auth:Jwt:Signing:Keys.");
            }
        }

        if (options.Jwt.TokenLifetime <= TimeSpan.Zero)
            failures.Add("Auth:Jwt:TokenLifetime must be positive.");

        if (options.RefreshTokens.Lifetime <= options.Jwt.TokenLifetime)
            failures.Add("Auth:RefreshTokens:Lifetime must be greater than Auth:Jwt:TokenLifetime.");

        if (options.Jwt.ClockSkew < TimeSpan.Zero)
            failures.Add("Auth:Jwt:ClockSkew must not be negative.");

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateAnnotated(object section, string sectionName, List<string> failures)
    {
        var ctx = new ValidationContext(section);
        var results = new List<ValidationResult>();
        if (!Validator.TryValidateObject(section, ctx, results, validateAllProperties: true))
            failures.AddRange(results.Select(r => $"Auth:{sectionName}: {r.ErrorMessage}"));
    }
}

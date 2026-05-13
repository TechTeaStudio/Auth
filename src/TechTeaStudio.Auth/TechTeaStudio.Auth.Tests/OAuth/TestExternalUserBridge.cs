using System.Collections.Concurrent;
using TechTeaStudio.Auth.OAuth;

namespace TechTeaStudio.Auth.Tests.OAuth;

/// <summary>In-memory user store used by OAuth flow tests. Mimics a real consumer's IUserRepository.</summary>
internal sealed class TestExternalUserBridge : IExternalUserBridge
{
    private readonly ConcurrentDictionary<string, ExternalUserSnapshot> _byId = new();
    private readonly ConcurrentDictionary<string, string> _idByEmail = new(StringComparer.OrdinalIgnoreCase);

    public Task<ExternalUserSnapshot?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(email)) return Task.FromResult<ExternalUserSnapshot?>(null);
        if (!_idByEmail.TryGetValue(email, out var id)) return Task.FromResult<ExternalUserSnapshot?>(null);
        _byId.TryGetValue(id, out var u);
        return Task.FromResult<ExternalUserSnapshot?>(u);
    }

    public Task<ExternalUserSnapshot?> GetByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        _byId.TryGetValue(userId, out var u);
        return Task.FromResult<ExternalUserSnapshot?>(u);
    }

    public Task<ExternalUserSnapshot> CreateFromExternalAsync(ExternalLoginInfo info, string username, CancellationToken cancellationToken = default)
    {
        var user = new ExternalUserSnapshot
        {
            UserId   = Guid.NewGuid().ToString("N"),
            Email    = info.Email ?? "",
            Username = username,
            PasswordHash = null,   // password-less
            Roles    = new[] { "user" },
        };
        _byId[user.UserId] = user;
        if (!string.IsNullOrEmpty(user.Email)) _idByEmail[user.Email] = user.UserId;
        return Task.FromResult(user);
    }

    /// <summary>Pre-seed a password user (for the RequiresPassword branch).</summary>
    public ExternalUserSnapshot SeedPasswordUser(string email, string passwordHash, string username = "preseed")
    {
        var user = new ExternalUserSnapshot
        {
            UserId       = Guid.NewGuid().ToString("N"),
            Email        = email,
            Username     = username,
            PasswordHash = passwordHash,
            Roles        = new[] { "user" },
        };
        _byId[user.UserId] = user;
        _idByEmail[email]  = user.UserId;
        return user;
    }
}

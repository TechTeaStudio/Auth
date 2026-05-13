using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.OAuth.GitHub;

public sealed class GitHubAuthProvider : IExternalAuthProvider
{
    public const string ProviderName = "GitHub";
    public string Name => ProviderName;

    private readonly HttpClient _http;
    private readonly IOptionsMonitor<GitHubAuthProviderOptions> _options;
    private readonly ILogger<GitHubAuthProvider>? _logger;

    public GitHubAuthProvider(
        HttpClient http,
        IOptionsMonitor<GitHubAuthProviderOptions> options,
        ILogger<GitHubAuthProvider>? logger = null)
    {
        _http = http;
        _options = options;
        _logger = logger;
    }

    public async Task<ExternalLoginInfo?> ValidateAsync(string rawCredential, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawCredential)) return null;

        var opts = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(opts.ClientId) || string.IsNullOrWhiteSpace(opts.ClientSecret))
        {
            _logger?.LogWarning("GitHub OAuth not configured (missing ClientId/ClientSecret)");
            return null;
        }

        try
        {
            var accessToken = await ExchangeCodeAsync(rawCredential, opts, ct);
            if (string.IsNullOrEmpty(accessToken)) return null;

            var profile = await GetUserProfileAsync(accessToken, opts, ct);
            if (profile is null) return null;

            var email = profile.Email;
            var emailVerified = !string.IsNullOrEmpty(email);
            if (string.IsNullOrEmpty(email))
            {
                var primary = await GetPrimaryEmailAsync(accessToken, opts, ct);
                if (primary is not null)
                {
                    email = primary.Email;
                    emailVerified = primary.Verified;
                }
            }

            if (opts.RequireEmailVerified && !emailVerified)
            {
                _logger?.LogInformation("GitHub user {Login} rejected: no verified email", profile.Login);
                return null;
            }

            return new ExternalLoginInfo(
                Provider: ProviderName,
                ProviderUserId: profile.Id.ToString(),
                Email: email ?? string.Empty,
                EmailVerified: emailVerified,
                DisplayName: !string.IsNullOrEmpty(profile.Name) ? profile.Name : profile.Login,
                AvatarUrl: profile.AvatarUrl,
                Extra: null);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "GitHub OAuth validation failed");
            return null;
        }
    }

    private async Task<string?> ExchangeCodeAsync(string code, GitHubAuthProviderOptions opts, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "https://github.com/login/oauth/access_token");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.UserAgent.ParseAdd(opts.UserAgent);
        req.Content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", opts.ClientId!),
            new KeyValuePair<string, string>("client_secret", opts.ClientSecret!),
            new KeyValuePair<string, string>("code", code),
        });

        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode) return null;

        var body = await resp.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);
        return body?.AccessToken;
    }

    private async Task<GitHubProfile?> GetUserProfileAsync(string accessToken, GitHubAuthProviderOptions opts, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        req.Headers.UserAgent.ParseAdd(opts.UserAgent);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode) return null;
        return await resp.Content.ReadFromJsonAsync<GitHubProfile>(cancellationToken: ct);
    }

    private async Task<GitHubEmail?> GetPrimaryEmailAsync(string accessToken, GitHubAuthProviderOptions opts, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/emails");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        req.Headers.UserAgent.ParseAdd(opts.UserAgent);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode) return null;

        var list = await resp.Content.ReadFromJsonAsync<List<GitHubEmail>>(cancellationToken: ct);
        return list?.FirstOrDefault(e => e.Primary && e.Verified)
            ?? list?.FirstOrDefault(e => e.Verified)
            ?? list?.FirstOrDefault();
    }

    private sealed class TokenResponse
    {
        [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [JsonPropertyName("token_type")]   public string? TokenType { get; set; }
        [JsonPropertyName("scope")]        public string? Scope { get; set; }
    }

    private sealed class GitHubProfile
    {
        [JsonPropertyName("id")]         public long Id { get; set; }
        [JsonPropertyName("login")]      public string Login { get; set; } = string.Empty;
        [JsonPropertyName("name")]       public string? Name { get; set; }
        [JsonPropertyName("email")]      public string? Email { get; set; }
        [JsonPropertyName("avatar_url")] public string? AvatarUrl { get; set; }
    }

    private sealed class GitHubEmail
    {
        [JsonPropertyName("email")]    public string Email { get; set; } = string.Empty;
        [JsonPropertyName("primary")]  public bool Primary { get; set; }
        [JsonPropertyName("verified")] public bool Verified { get; set; }
    }
}

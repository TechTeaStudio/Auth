namespace TechTeaStudio.Auth.OAuth.GitHub;

public sealed class GitHubAuthProviderOptions
{
    /// <summary>Client ID of the GitHub OAuth App.</summary>
    public string? ClientId { get; set; }

    /// <summary>Client Secret for the OAuth App. Required for the code → access_token exchange.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>If true, only accept emails marked as primary AND verified in GitHub's account.</summary>
    public bool RequireEmailVerified { get; set; } = true;

    /// <summary>User-Agent header sent on outbound GitHub API calls. GitHub rejects requests without one.</summary>
    public string UserAgent { get; set; } = "TechTeaStudio.Auth.OAuth.GitHub";
}

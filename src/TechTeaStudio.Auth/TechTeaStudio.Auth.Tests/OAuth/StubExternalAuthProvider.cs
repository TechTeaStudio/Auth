using TechTeaStudio.Auth.OAuth;

namespace TechTeaStudio.Auth.Tests.OAuth;

/// <summary>Drives the orchestrator without needing a real provider SDK. Each fake
/// token is just a key into a dictionary of pre-baked <see cref="ExternalLoginInfo"/>s.</summary>
internal sealed class StubExternalAuthProvider : IExternalAuthProvider
{
    public string Name { get; }
    public Dictionary<string, ExternalLoginInfo?> Responses { get; } = new();

    public StubExternalAuthProvider(string name = "Stub") => Name = name;

    public Task<ExternalLoginInfo?> ValidateAsync(string rawCredential, CancellationToken cancellationToken = default)
    {
        Responses.TryGetValue(rawCredential, out var info);
        return Task.FromResult(info);
    }
}

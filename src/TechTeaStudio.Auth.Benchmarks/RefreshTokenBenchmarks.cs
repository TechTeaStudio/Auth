using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.RefreshTokens;

namespace TechTeaStudio.Auth.Benchmarks;

[MemoryDiagnoser]
public class RefreshTokenBenchmarks
{
    private RefreshTokenService _service = null!;
    private string _seededRefresh = "";

    [GlobalSetup]
    public void Setup()
    {
        var opts = Options.Create(new AuthOptions
        {
            SecretKey = "benchmark-signing-key-32-chars-!",
            Issuer = "tts.bench",
            Audience = "tts.bench.clients",
        });
        var provider = JwtTokenProvider.ForOptions(opts);
        var store = new InMemoryRefreshTokenStore();
        _service = new RefreshTokenService(provider, store, opts);

        var pair = _service.IssueAsync("u", Array.Empty<Claim>()).GetAwaiter().GetResult();
        _seededRefresh = pair.RefreshToken;
    }

    [Benchmark]
    public TokenPair Issue() =>
        _service.IssueAsync("u", Array.Empty<Claim>()).GetAwaiter().GetResult();

    [Benchmark]
    public string HashRefreshToken() =>
        TokenHasher.HashRefreshToken(_seededRefresh);

    [Benchmark]
    public string NewRawToken() => TokenHasher.NewRawToken();
}

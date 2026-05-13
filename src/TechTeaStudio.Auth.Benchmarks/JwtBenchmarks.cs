using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Jwt;

namespace TechTeaStudio.Auth.Benchmarks;

[MemoryDiagnoser]
public class JwtBenchmarks
{
    private JwtTokenProvider _provider = null!;
    private string _token = "";

    private readonly Claim[] _claims =
    {
        new(AuthClaims.Username, "bench-user"),
        new(AuthClaims.Email, "u@x"),
        new(AuthClaims.Role, "admin"),
    };

    [GlobalSetup]
    public void Setup()
    {
        var opts = Options.Create(new AuthOptions
        {
            Jwt =
            {
                SecretKey = "benchmark-signing-key-32-chars-!",
                Issuer = "tts.bench",
                Audience = "tts.bench.clients",
            },
        });
        _provider = JwtTokenProvider.ForOptions(opts);
        _token = _provider.CreateToken("u", _claims, TimeSpan.FromMinutes(5));
    }

    [Benchmark]
    public string CreateToken() =>
        _provider.CreateToken("u", _claims, TimeSpan.FromMinutes(5));

    [Benchmark]
    public ClaimsPrincipal? ValidateToken() =>
        _provider.ValidateToken(_token);

    [Benchmark]
    public AuthTokenInfo? TryRead() =>
        new JwtTokenReader().TryRead(_token);
}

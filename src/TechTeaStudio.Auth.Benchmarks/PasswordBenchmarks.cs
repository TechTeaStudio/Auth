using BenchmarkDotNet.Attributes;
using TechTeaStudio.Auth.Passwords;

namespace TechTeaStudio.Auth.Benchmarks;

[MemoryDiagnoser]
public class PasswordBenchmarks
{
    private readonly Pbkdf2PasswordHasher _hasher = new();
    private string _hash = "";
    private const string Password = "correct horse battery staple";

    [GlobalSetup]
    public void Setup() => _hash = _hasher.Hash(Password);

    [Benchmark]
    public string Hash() => _hasher.Hash(Password);

    [Benchmark]
    public bool VerifyCorrect() => _hasher.Verify(_hash, Password);

    [Benchmark]
    public bool VerifyWrong() => _hasher.Verify(_hash, "wrong horse battery staple");
}

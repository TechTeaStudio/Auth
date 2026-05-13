using BenchmarkDotNet.Running;
using TechTeaStudio.Auth.Benchmarks;

BenchmarkSwitcher.FromTypes(new[]
{
    typeof(JwtBenchmarks),
    typeof(PasswordBenchmarks),
    typeof(RefreshTokenBenchmarks),
}).Run(args);

# TechTeaStudio.Auth.Benchmarks

BenchmarkDotNet runner for the hot paths in `TechTeaStudio.Auth`.

## Run

```bash
# Run every benchmark
dotnet run -c Release --project src/TechTeaStudio.Auth.Benchmarks --framework net9.0 -- --filter "*"

# Just the JWT class
dotnet run -c Release --project src/TechTeaStudio.Auth.Benchmarks --framework net9.0 -- --filter "*JwtBenchmarks*"
```

Targets are `net9.0` and `net10.0` — pass `--framework` to pick one. The `--filter` switch follows BenchmarkDotNet's standard glob syntax.

## What gets measured

| Class | Methods | What it answers |
|---|---|---|
| `JwtBenchmarks` | `CreateToken`, `ValidateToken`, `TryRead` | Cost of issuing, validating, and parsing an HS256 JWT. |
| `PasswordBenchmarks` | `Hash`, `VerifyCorrect`, `VerifyWrong` | PBKDF2-SHA256 cost at the shipping iteration count. |
| `RefreshTokenBenchmarks` | `Issue`, `HashRefreshToken`, `NewRawToken` | End-to-end refresh-token issuance and the SHA-256 hash step. |

All classes carry `[MemoryDiagnoser]`, so allocation counts and Gen0/1/2 are reported alongside the timings.

## Interpreting the numbers

- **PBKDF2 is intentionally slow.** `Hash` and `Verify` should land around 200–300 ms each at 600 000 iterations — that is the cost of brute-force resistance.
- **JWT round-trip should be measured in microseconds.** A `CreateToken` + `ValidateToken` pair under 1 ms is the goal.
- **Allocations.** `TokenHasher.HashRefreshToken` and `TokenHasher.NewRawToken` allocate a small `byte[]` each call — anything above a single Gen0 collection per million ops is a regression.

Numbers from a reference run live alongside this README in `BenchmarkDotNet.Artifacts/` after the first run — commit the summary table back to the repo when you update the shipping iteration count.

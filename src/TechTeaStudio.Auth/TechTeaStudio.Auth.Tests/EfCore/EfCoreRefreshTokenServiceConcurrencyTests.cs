using System.Security.Claims;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.EFCore;
using TechTeaStudio.Auth.Jwt;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Tests.TestHelpers;
using Xunit;

namespace TechTeaStudio.Auth.Tests.EfCore;

/// <summary>
/// Reproduces the <see cref="RefreshTokenService.RotateAsync(string, IEnumerable{Claim}, CancellationToken)"/>
/// double-spend/fork race: two independent <see cref="RefreshTokenService"/>
/// instances (mirroring two app-server processes), each backed by its own
/// <see cref="TestDbContext"/> sharing one Sqlite connection — the same fixture
/// shape as <see cref="EfCoreRefreshTokenStoreConcurrencyTests"/> — rotate the
/// SAME presented token at once.
/// </summary>
/// <remarks>
/// Microsoft.Data.Sqlite does not support truly concurrent command execution on
/// one shared <see cref="SqliteConnection"/>, so a coordinator is used instead of
/// raw <c>Task.WhenAll</c> timing: a rendezvous barrier guarantees both sides'
/// reads observe the token as active before either side attempts to write, and a
/// mutex serializes every actual DB call so no two commands ever run concurrently
/// on the shared connection. The CAS in <see cref="IRefreshTokenStore.RevokeAsync"/>
/// still resolves the race correctly regardless of which side's write lands first.
/// </remarks>
public sealed class EfCoreRefreshTokenServiceConcurrencyTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<TestDbContext> _options;

    public EfCoreRefreshTokenServiceConcurrencyTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<TestDbContext>().UseSqlite(_connection).Options;
        using var schemaCtx = new TestDbContext(_options);
        schemaCtx.Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private sealed class ReadRendezvous
    {
        public readonly SemaphoreSlim DbMutex = new(1, 1);
        private readonly SemaphoreSlim _bothArrived = new(0, 1);
        private int _arrivals;

        public async Task WaitForBothReadersAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _arrivals) == 2) _bothArrived.Release();
            else await _bothArrived.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Wraps an <see cref="EfCoreRefreshTokenStore{TContext}"/> so every DB call is
    /// serialized through <see cref="ReadRendezvous.DbMutex"/>, and the read for
    /// <paramref name="gatedHash"/> blocks until the counterpart store's read for
    /// the same hash has also landed.
    /// </summary>
    private sealed class CoordinatedStore : IRefreshTokenStore
    {
        private readonly IRefreshTokenStore _inner;
        private readonly ReadRendezvous _coord;
        private readonly string _gatedHash;

        public CoordinatedStore(IRefreshTokenStore inner, ReadRendezvous coord, string gatedHash)
        {
            _inner = inner;
            _coord = coord;
            _gatedHash = gatedHash;
        }

        public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            RefreshToken? result;
            try { result = await _inner.GetByTokenHashAsync(tokenHash, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }

            if (tokenHash == _gatedHash) await _coord.WaitForBothReadersAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }

        public async Task<IReadOnlyList<RefreshToken>> GetActiveForUserAsync(string userId, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return await _inner.GetActiveForUserAsync(userId, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }
        }

        public async Task CreateAsync(RefreshToken token, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _inner.CreateAsync(token, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }
        }

        public async Task<bool> RevokeAsync(Guid id, string? replacedByTokenHash = null, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return await _inner.RevokeAsync(id, replacedByTokenHash, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }
        }

        public async Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _inner.RevokeAllForUserAsync(userId, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }
        }

        public async Task<int> RevokeFamilyAsync(Guid familyId, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return await _inner.RevokeFamilyAsync(familyId, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }
        }

        public async Task<int> CleanupExpiredAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return await _inner.CleanupExpiredAsync(cutoff, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }
        }

        public async Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default)
        {
            await _coord.DbMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { await _inner.DeleteAllForUserAsync(userId, cancellationToken).ConfigureAwait(false); }
            finally { _coord.DbMutex.Release(); }
        }
    }

    [Fact]
    public async Task RotateAsync_two_concurrent_rotations_of_the_same_token_only_one_wins()
    {
        var concrete = TestAuthOptions.Create();
        var provider = new JwtTokenProvider(concrete.ToMonitor());
        var opts = Options.Create(concrete);

        using var seedContext = new TestDbContext(_options);
        var seedService = new RefreshTokenService(provider, new EfCoreRefreshTokenStore<TestDbContext>(seedContext), opts);
        var issued = await seedService.IssueAsync("u-fork", Array.Empty<Claim>());
        var presentedHash = TokenHasher.HashRefreshToken(issued.RefreshToken);

        var coord = new ReadRendezvous();
        using var contextA = new TestDbContext(_options);
        using var contextB = new TestDbContext(_options);
        var storeA = new CoordinatedStore(new EfCoreRefreshTokenStore<TestDbContext>(contextA), coord, presentedHash);
        var storeB = new CoordinatedStore(new EfCoreRefreshTokenStore<TestDbContext>(contextB), coord, presentedHash);
        var serviceA = new RefreshTokenService(provider, storeA, opts);
        var serviceB = new RefreshTokenService(provider, storeB, opts);

        var taskA = serviceA.RotateAsync(issued.RefreshToken, Array.Empty<Claim>());
        var taskB = serviceB.RotateAsync(issued.RefreshToken, Array.Empty<Claim>());
        var results = await Task.WhenAll(taskA, taskB);

        // On the pre-fix code (create-then-revoke, ignoring RevokeAsync's result)
        // both sides would have observed the token as active and both would have
        // created a successor — two live tokens for one rotation chain.
        results.Count(r => r is not null).Should().Be(1);
        results.Count(r => r is null).Should().Be(1);

        using var verifyContext = new TestDbContext(_options);
        var verifyStore = new EfCoreRefreshTokenStore<TestDbContext>(verifyContext);
        var actives = await verifyStore.GetActiveForUserAsync("u-fork");
        actives.Should().HaveCount(1);
    }
}

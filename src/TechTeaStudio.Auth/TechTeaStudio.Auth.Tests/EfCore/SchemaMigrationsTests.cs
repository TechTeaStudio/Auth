using FluentAssertions;
using Microsoft.Data.Sqlite;
using TechTeaStudio.Auth.EFCore;
using Xunit;

namespace TechTeaStudio.Auth.Tests.EfCore;

/// <summary>
/// Exercises the 0.10.0 <c>FamilyId</c> upgrade SQL against a real Sqlite connection: a
/// pre-0.10.0 table (no <c>FamilyId</c> column) gets the column added, existing rows are
/// backfilled with a valid, distinct GUID each, and re-applying under the documented
/// <c>pragma_table_info</c> guard is a no-op rather than a duplicate-column error.
/// </summary>
public sealed class SchemaMigrationsTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public SchemaMigrationsTests()
    {
        _connection.Open();
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE "TtsRefreshTokens" (
                "Id" TEXT NOT NULL PRIMARY KEY,
                "UserId" TEXT NOT NULL,
                "TokenHash" TEXT NOT NULL,
                "ExpiresAt" TEXT NOT NULL
            );
            INSERT INTO "TtsRefreshTokens" ("Id","UserId","TokenHash","ExpiresAt")
            VALUES ('11111111-1111-1111-1111-111111111111', 'u-1', 'hash-1', '2099-01-01T00:00:00Z');
            INSERT INTO "TtsRefreshTokens" ("Id","UserId","TokenHash","ExpiresAt")
            VALUES ('22222222-2222-2222-2222-222222222222', 'u-2', 'hash-2', '2099-01-01T00:00:00Z');
            """;
        cmd.ExecuteNonQuery();
    }

    public void Dispose() => _connection.Dispose();

    private async Task<bool> HasFamilyIdColumnAsync()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM pragma_table_info('TtsRefreshTokens') WHERE name = 'FamilyId'";
        return (long)(await cmd.ExecuteScalarAsync())! > 0;
    }

    private async Task ApplyGuardedAsync()
    {
        if (await HasFamilyIdColumnAsync()) return;
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = SchemaMigrations.AddFamilyIdColumnSqlSqlite();
        await cmd.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task AddFamilyIdColumnSqlSqlite_adds_the_column()
    {
        await ApplyGuardedAsync();
        (await HasFamilyIdColumnAsync()).Should().BeTrue();
    }

    [Fact]
    public async Task AddFamilyIdColumnSqlSqlite_backfills_existing_rows_with_valid_distinct_guids()
    {
        await ApplyGuardedAsync();

        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """SELECT "Id", "FamilyId" FROM "TtsRefreshTokens" ORDER BY "Id" """;
        using var reader = await cmd.ExecuteReaderAsync();

        var familyIds = new List<string>();
        while (await reader.ReadAsync())
        {
            var familyId = reader.GetString(1);
            Guid.TryParse(familyId, out _).Should().BeTrue();
            familyIds.Add(familyId);
        }

        familyIds.Should().HaveCount(2);
        familyIds[0].Should().NotBe(familyIds[1]);
    }

    [Fact]
    public async Task AddFamilyIdColumnSqlSqlite_reapplied_under_the_documented_guard_is_a_noop()
    {
        await ApplyGuardedAsync();
        var act = ApplyGuardedAsync;
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public void AddFamilyIdColumnSqlPostgres_guards_with_IF_NOT_EXISTS()
    {
        SchemaMigrations.AddFamilyIdColumnSqlPostgres().Should().Contain("ADD COLUMN IF NOT EXISTS \"FamilyId\"");
    }

    [Fact]
    public void AddFamilyIdColumnSqlSqlServer_guards_with_COL_LENGTH()
    {
        SchemaMigrations.AddFamilyIdColumnSqlSqlServer().Should().Contain("COL_LENGTH('TtsRefreshTokens', 'FamilyId')");
    }
}

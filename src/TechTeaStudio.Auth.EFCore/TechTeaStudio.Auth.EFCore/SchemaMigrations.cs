namespace TechTeaStudio.Auth.EFCore;

/// <summary>
/// Hand-written SQL snippets consumers can apply to upgrade an existing
/// <c>TtsRefreshTokens</c> table when a schema-affecting release ships.
///
/// <para>
/// The library does not run EF Core migrations on the consumer's behalf — we
/// only describe the entity via <see cref="ModelBuilderExtensions.AddTechTeaStudioRefreshTokens"/>.
/// Fresh deployments get the columns automatically (EnsureCreated / first
/// migration). Existing deployments need a one-line <c>ALTER TABLE</c>.
/// </para>
/// </summary>
public static class SchemaMigrations
{
    /// <summary>
    /// 0.8.0 upgrade for an existing <c>TtsRefreshTokens</c> table. Adds three columns
    /// the <see cref="RefreshTokenEntity"/> grew in this release:
    /// <list type="bullet">
    ///   <item><c>DeviceId</c> (nullable varchar(256))</item>
    ///   <item><c>DeviceInfo</c> (nullable varchar(64))</item>
    ///   <item><c>ConcurrencyStamp</c> (NOT NULL varchar(64), defaulted via <c>gen_random_uuid()::text</c>
    ///     so pre-existing rows backfill safely)</item>
    /// </list>
    /// PostgreSQL syntax. Idempotent — safe to re-run.
    /// <para>
    /// <strong>Heads-up:</strong> versions 0.8.0 and 0.8.1 of this method shipped without the
    /// <c>ConcurrencyStamp</c> ALTER, and that's a hard production blocker — without the column,
    /// <see cref="EfCoreRefreshTokenStore{TContext}.CreateAsync"/> throws <c>DbUpdateConcurrencyException</c>
    /// on every INSERT, breaking login / register / refresh end-to-end. Always run the latest
    /// version of this helper after upgrading the package.
    /// </para>
    /// </summary>
    public static string AddDeviceColumnsSqlPostgres(string tableName = "TtsRefreshTokens") =>
        $"""
        ALTER TABLE "{tableName}" ADD COLUMN IF NOT EXISTS "DeviceId"         varchar(256) NULL;
        ALTER TABLE "{tableName}" ADD COLUMN IF NOT EXISTS "DeviceInfo"       varchar(64)  NULL;
        ALTER TABLE "{tableName}" ADD COLUMN IF NOT EXISTS "ConcurrencyStamp" varchar(64)  NOT NULL DEFAULT gen_random_uuid()::text;
        """;

    /// <summary>
    /// 0.8.0 upgrade SQL for SQL Server (no <c>IF NOT EXISTS</c> for columns — guarded
    /// via <c>sys.columns</c>). Adds <c>DeviceId</c>, <c>DeviceInfo</c>, and
    /// <c>ConcurrencyStamp</c> (backfilled with <c>NEWID()</c> for existing rows).
    /// </summary>
    public static string AddDeviceColumnsSqlSqlServer(string tableName = "TtsRefreshTokens") =>
        $"""
        IF COL_LENGTH('{tableName}', 'DeviceId') IS NULL
            ALTER TABLE [{tableName}] ADD [DeviceId] nvarchar(256) NULL;
        IF COL_LENGTH('{tableName}', 'DeviceInfo') IS NULL
            ALTER TABLE [{tableName}] ADD [DeviceInfo] nvarchar(64) NULL;
        IF COL_LENGTH('{tableName}', 'ConcurrencyStamp') IS NULL
            ALTER TABLE [{tableName}] ADD [ConcurrencyStamp] nvarchar(64) NOT NULL
                CONSTRAINT [DF_{tableName}_ConcurrencyStamp] DEFAULT CONVERT(nvarchar(64), NEWID());
        """;

    /// <summary>
    /// 0.8.0 upgrade SQL for SQLite (no native <c>IF NOT EXISTS</c> on ADD COLUMN — caller
    /// should run inside a try/catch or check <c>pragma_table_info</c> first). Adds the
    /// same three columns; <c>ConcurrencyStamp</c> defaults to a 32-hex-char random value.
    /// </summary>
    public static string AddDeviceColumnsSqlSqlite(string tableName = "TtsRefreshTokens") =>
        $"""
        ALTER TABLE "{tableName}" ADD COLUMN "DeviceId"         TEXT NULL;
        ALTER TABLE "{tableName}" ADD COLUMN "DeviceInfo"       TEXT NULL;
        ALTER TABLE "{tableName}" ADD COLUMN "ConcurrencyStamp" TEXT NOT NULL DEFAULT (lower(hex(randomblob(16))));
        """;
}

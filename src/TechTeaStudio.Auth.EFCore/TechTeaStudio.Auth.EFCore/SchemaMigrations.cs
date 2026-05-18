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
    /// 0.8.0 upgrade: adds <c>DeviceId</c> and <c>DeviceInfo</c> nullable columns.
    /// PostgreSQL syntax (idempotent — safe to re-run).
    /// </summary>
    public static string AddDeviceColumnsSqlPostgres(string tableName = "TtsRefreshTokens") =>
        $"""
        ALTER TABLE "{tableName}" ADD COLUMN IF NOT EXISTS "DeviceId"   varchar(256) NULL;
        ALTER TABLE "{tableName}" ADD COLUMN IF NOT EXISTS "DeviceInfo" varchar(64)  NULL;
        """;

    /// <summary>
    /// 0.8.0 upgrade SQL for SQL Server (no <c>IF NOT EXISTS</c> for columns — guarded
    /// via <c>sys.columns</c>).
    /// </summary>
    public static string AddDeviceColumnsSqlSqlServer(string tableName = "TtsRefreshTokens") =>
        $"""
        IF COL_LENGTH('{tableName}', 'DeviceId') IS NULL
            ALTER TABLE [{tableName}] ADD [DeviceId] nvarchar(256) NULL;
        IF COL_LENGTH('{tableName}', 'DeviceInfo') IS NULL
            ALTER TABLE [{tableName}] ADD [DeviceInfo] nvarchar(64) NULL;
        """;

    /// <summary>
    /// 0.8.0 upgrade SQL for SQLite (no native <c>IF NOT EXISTS</c> on ADD COLUMN — caller
    /// should run inside a try/catch or check <c>pragma_table_info</c> first).
    /// </summary>
    public static string AddDeviceColumnsSqlSqlite(string tableName = "TtsRefreshTokens") =>
        $"""
        ALTER TABLE "{tableName}" ADD COLUMN "DeviceId"   TEXT NULL;
        ALTER TABLE "{tableName}" ADD COLUMN "DeviceInfo" TEXT NULL;
        """;
}

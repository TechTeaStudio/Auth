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

    /// <summary>
    /// 0.10.0 upgrade for an existing <c>TtsRefreshTokens</c> table. Adds the non-nullable
    /// <c>FamilyId</c> (uuid) column stolen-token (reuse) detection needs to burn an entire
    /// rotation family in one statement instead of walking <c>ReplacedByTokenHash</c> hop by hop.
    /// PostgreSQL syntax. Idempotent — safe to re-run.
    /// <para>
    /// <c>gen_random_uuid()</c> is volatile, so PostgreSQL evaluates it once per EXISTING row
    /// rather than taking the single-value fast path — every pre-migration row is backfilled
    /// with its OWN distinct random <c>FamilyId</c> (a family of one), not a shared value.
    /// </para>
    /// <para>
    /// <strong>Known limitation:</strong> a pre-migration row's ACTUAL predecessor/successor
    /// chain — recorded only via <c>ReplacedByTokenHash</c> pointers, not by any shared grouping
    /// column before this release — is not reconstructed. Such a row keeps validating and
    /// rotating normally, and reuse-detection on it still revokes it correctly, but only
    /// itself: it will not also revoke a pre-migration predecessor/successor the way it would
    /// have under the old chain-walk. Any FRESH rotation issued after this migration correctly
    /// carries the real shared <c>FamilyId</c> forward from that point on — this is strictly a
    /// one-time, one-boundary gap for tokens already in flight at upgrade time, not an ongoing one.
    /// </para>
    /// </summary>
    public static string AddFamilyIdColumnSqlPostgres(string tableName = "TtsRefreshTokens") =>
        $"""
        ALTER TABLE "{tableName}" ADD COLUMN IF NOT EXISTS "FamilyId" uuid NOT NULL DEFAULT gen_random_uuid();
        """;

    /// <summary>
    /// 0.10.0 upgrade SQL for SQL Server (no <c>IF NOT EXISTS</c> for columns — guarded via
    /// <c>COL_LENGTH</c>). Adds <c>FamilyId</c>, backfilled per-row via <c>NEWID()</c> (a
    /// non-constant default, so — like <c>gen_random_uuid()</c> on Postgres — SQL Server
    /// evaluates it once per existing row rather than reusing one shared value). See
    /// <see cref="AddFamilyIdColumnSqlPostgres"/> for the same backfill/limitation notes.
    /// </summary>
    public static string AddFamilyIdColumnSqlSqlServer(string tableName = "TtsRefreshTokens") =>
        $"""
        IF COL_LENGTH('{tableName}', 'FamilyId') IS NULL
            ALTER TABLE [{tableName}] ADD [FamilyId] uniqueidentifier NOT NULL
                CONSTRAINT [DF_{tableName}_FamilyId] DEFAULT NEWID();
        """;

    /// <summary>
    /// 0.10.0 upgrade SQL for SQLite (no native <c>IF NOT EXISTS</c> on ADD COLUMN — caller
    /// should run inside a try/catch or check <c>pragma_table_info</c> first, exactly like
    /// <see cref="AddDeviceColumnsSqlSqlite"/>). Adds <c>FamilyId</c> as TEXT, then backfills it
    /// with a canonical (hyphenated, lower-case) random GUID string per row — matching the
    /// format EF Core's Sqlite provider expects when reading the column back as <see cref="Guid"/> —
    /// via the standard "generate a UUID v4 from randomblob" SQLite idiom (there is no built-in
    /// UUID function). Two statements, not one: SQLite's <c>ALTER TABLE ... ADD COLUMN</c> only
    /// accepts a CONSTANT default (<c>Cannot add a column with non-constant default</c> for
    /// anything involving a function call), unlike PostgreSQL/SQL Server, so the column is added
    /// with a constant placeholder default first and backfilled by a separate <c>UPDATE</c>,
    /// which has no such restriction. See <see cref="AddFamilyIdColumnSqlPostgres"/> for the
    /// backfill/limitation notes.
    /// </summary>
    public static string AddFamilyIdColumnSqlSqlite(string tableName = "TtsRefreshTokens") =>
        $"""
        ALTER TABLE "{tableName}" ADD COLUMN "FamilyId" TEXT NOT NULL DEFAULT '';
        UPDATE "{tableName}" SET "FamilyId" = lower(
            hex(randomblob(4)) || '-' ||
            hex(randomblob(2)) || '-' ||
            '4' || substr(hex(randomblob(2)), 2) || '-' ||
            substr('89ab', abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)), 2) || '-' ||
            hex(randomblob(6))
        ) WHERE "FamilyId" = '';
        """;
}

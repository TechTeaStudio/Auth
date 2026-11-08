using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Internal;

namespace TechTeaStudio.Auth.OAuthServer.Clients;

/// <summary>Process-wide cache of fetched client metadata documents (positive and short negative entries).</summary>
internal sealed class ClientMetadataCache
{
    private const int MaxEntries = 2000;
    private readonly ConcurrentDictionary<string, (OAuthClient? Client, DateTimeOffset Expires)> _items = new(StringComparer.Ordinal);

    public bool TryGet(string key, DateTimeOffset now, out OAuthClient? client)
    {
        client = null;
        if (!_items.TryGetValue(key, out var e)) return false;
        if (e.Expires <= now)
        {
            _items.TryRemove(key, out _);
            return false;
        }
        client = e.Client;
        return true;
    }

    public void Set(string key, OAuthClient? client, DateTimeOffset expires, DateTimeOffset now)
    {
        if (_items.Count >= MaxEntries)
        {
            foreach (var kv in _items)
                if (kv.Value.Expires <= now) _items.TryRemove(kv.Key, out _);
            if (_items.Count >= MaxEntries) _items.Clear();
        }
        _items[key] = (client, expires);
    }
}

/// <summary>Resolves a client_id: pre-registered (options), then stored (DCR), then Client ID Metadata Document.</summary>
internal sealed class OAuthClientResolver
{
    private static readonly TimeSpan NegativeCache = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TouchInterval = TimeSpan.FromHours(1);

    private readonly OAuthServerOptions _options;
    private readonly IOAuthClientStore _store;
    private readonly ClientMetadataCache _cache;
    private readonly IClientMetadataFetcher _fetcher;
    private readonly IAuthAuditLogger _audit;
    private readonly TimeProvider _time;

    public OAuthClientResolver(
        IOptions<OAuthServerOptions> options, IOAuthClientStore store, ClientMetadataCache cache,
        IClientMetadataFetcher fetcher, IAuthAuditLogger audit, TimeProvider time)
    {
        _options = options.Value;
        _store = store;
        _cache = cache;
        _fetcher = fetcher;
        _audit = audit;
        _time = time;
    }

    public async Task<OAuthClient?> ResolveAsync(string? clientId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(clientId) || clientId.Length > 512) return null;

        var configured = _options.Clients.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));
        if (configured is not null)
            return new OAuthClient
            {
                ClientId = configured.ClientId,
                Name = configured.Name,
                LogoUri = configured.LogoUri,
                ClientUri = configured.ClientUri,
                RedirectUris = configured.RedirectUris.ToArray(),
                SecretHash = string.IsNullOrEmpty(configured.ClientSecret) ? null : OAuthSecrets.Hash(configured.ClientSecret),
                Source = OAuthClientSource.PreRegistered,
                CreatedAt = _time.GetUtcNow(),
            };

        var stored = await _store.FindAsync(clientId, ct).ConfigureAwait(false);
        if (stored is not null)
        {
            var seen = _time.GetUtcNow();
            if (stored.Source == OAuthClientSource.Dynamic && (stored.LastUsedAt is null || seen - stored.LastUsedAt.Value >= TouchInterval))
                await _store.TouchAsync(stored.ClientId, seen, ct).ConfigureAwait(false);
            return stored;
        }

        if (!_options.EnableClientIdMetadataDocuments || !ClientMetadataParser.IsMetadataDocumentUrl(clientId, out var url))
            return null;

        var now = _time.GetUtcNow();
        if (_cache.TryGet(clientId, now, out var cached)) return cached;

        ClientMetadataFetchResult fetched;
        try
        {
            fetched = await _fetcher.FetchAsync(url, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            fetched = ClientMetadataFetchResult.Fail("fetcher_error");
        }
        if (!fetched.Succeeded)
        {
            await Fail(clientId, fetched.Error ?? "fetch_failed", now, ct).ConfigureAwait(false);
            return null;
        }

        var client = ClientMetadataParser.ParseDocument(fetched.Json!, clientId, _options, now, out var reason);
        if (client is null)
        {
            await Fail(clientId, reason ?? "invalid_document", now, ct).ConfigureAwait(false);
            return null;
        }

        var ttl = fetched.MaxAge ?? _options.ClientMetadataDefaultCache;
        if (ttl > _options.ClientMetadataMaxCache) ttl = _options.ClientMetadataMaxCache;
        if (ttl > TimeSpan.Zero) _cache.Set(clientId, client, now + ttl, now);
        return client;
    }

    private async Task Fail(string clientId, string reason, DateTimeOffset now, CancellationToken ct)
    {
        _cache.Set(clientId, null, now + NegativeCache, now);
        await _audit.LogAsync(new OAuthClientMetadataFetchFailedEvent(clientId, reason, now), ct).ConfigureAwait(false);
    }
}

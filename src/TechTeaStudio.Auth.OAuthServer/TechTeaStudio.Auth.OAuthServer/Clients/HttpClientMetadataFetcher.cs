using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.OAuthServer.Abstractions;
using TechTeaStudio.Auth.OAuthServer.Internal;

namespace TechTeaStudio.Auth.OAuthServer.Clients;

/// <summary>
/// Default <see cref="IClientMetadataFetcher"/>. https only, no redirects, no proxy, short timeout, capped body, and an
/// SSRF guard applied at CONNECT time: the address the socket actually dials is checked, so DNS rebinding between a
/// "check" and a "use" cannot slip a private address through.
/// </summary>
public sealed class HttpClientMetadataFetcher : IClientMetadataFetcher, IDisposable
{
    private readonly HttpClient _http;
    private readonly int _maxBytes;
    private readonly TimeSpan _timeout;

    public HttpClientMetadataFetcher(IOptions<OAuthServerOptions> options)
    {
        var o = options.Value;
        _maxBytes = o.MaxClientMetadataBytes;
        _timeout = o.ClientMetadataFetchTimeout;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = _timeout,
            ConnectCallback = ConnectGuardedAsync,
        };
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public void Dispose() => _http.Dispose();

    public async Task<ClientMetadataFetchResult> FetchAsync(Uri url, CancellationToken cancellationToken = default)
    {
        if (url.Scheme != Uri.UriSchemeHttps) return ClientMetadataFetchResult.Fail("not_https");
        if (IPAddress.TryParse(url.Host.Trim('[', ']'), out var literal) && !OutboundAddressPolicy.IsPublic(literal))
            return ClientMetadataFetchResult.Fail("blocked_address");

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);

            var status = (int)response.StatusCode;
            if (status is >= 300 and < 400) return ClientMetadataFetchResult.Fail("redirect_refused");
            if (status != 200) return ClientMetadataFetchResult.Fail("http_" + status);

            var mediaType = response.Content.Headers.ContentType?.MediaType;
            if (mediaType is null || mediaType.IndexOf("json", StringComparison.OrdinalIgnoreCase) < 0)
                return ClientMetadataFetchResult.Fail("not_json");
            if (response.Content.Headers.ContentLength is { } len && len > _maxBytes)
                return ClientMetadataFetchResult.Fail("too_large");

            await using var stream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            int read;
            while ((read = await stream.ReadAsync(chunk.AsMemory(), cts.Token).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > _maxBytes) return ClientMetadataFetchResult.Fail("too_large");
                buffer.Write(chunk, 0, read);
            }

            TimeSpan? maxAge = null;
            var cc = response.Headers.CacheControl;
            if (cc is not null)
            {
                if (cc.NoStore || cc.NoCache) maxAge = TimeSpan.Zero;
                else if (cc.MaxAge is { } m) maxAge = m;
            }

            return ClientMetadataFetchResult.Ok(System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length), maxAge);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ClientMetadataFetchResult.Fail("timeout");
        }
        catch (HttpRequestException)
        {
            return ClientMetadataFetchResult.Fail("unreachable_or_blocked");
        }
    }

    private static async ValueTask<Stream> ConnectGuardedAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(a => !OutboundAddressPolicy.IsPublic(a)))
            throw new HttpRequestException("Destination address is not allowed.");

        Exception? last = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (ex is SocketException)
            {
                socket.Dispose();
                last = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
        throw new HttpRequestException("Could not connect.", last);
    }
}

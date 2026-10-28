using System.Security.Cryptography;
using System.Text.Json;

namespace OpenClawNew.P0;

internal sealed record Request(int Version, string RequestId, string Nonce, DateTimeOffset IssuedAtUtc, string Operation, JsonElement Args);
internal sealed record Response(bool Ok, string RequestId, string Code, object? Result = null);

internal sealed class ProtocolError(string code) : Exception(code)
{
    public string Code { get; } = code;
}

internal sealed class ReplayGuard
{
    private readonly Dictionary<string, DateTimeOffset> seen = new(StringComparer.Ordinal);
    private readonly object gate = new();
    public void Admit(Request request, DateTimeOffset now)
    {
        if (request.Version != 1) throw new ProtocolError("VERSION_UNSUPPORTED");
        if (!Guid.TryParseExact(request.RequestId, "D", out _) ||
            !Guid.TryParseExact(request.Nonce, "D", out _))
            throw new ProtocolError("INVALID_ID");
        if ((now - request.IssuedAtUtc).Duration() > TimeSpan.FromMinutes(2))
            throw new ProtocolError("EXPIRED");
        lock (gate)
        {
            foreach (var key in seen.Where(x => x.Value < now).Select(x => x.Key).ToArray())
                seen.Remove(key);
            if (seen.ContainsKey(request.Nonce)) throw new ProtocolError("REPLAY");
            if (seen.Count >= 4096) throw new ProtocolError("REPLAY_CAPACITY");
            seen.Add(request.Nonce, now.AddMinutes(3));
        }
    }
}

internal static class Wire
{
    public const int MaxBytes = 16384;
    public static async Task<byte[]> ReadAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct);
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length < 2 || length > MaxBytes) throw new ProtocolError("FRAME_SIZE");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, ct);
        return payload;
    }

    public static async Task WriteAsync(Stream stream, object payload, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        if (bytes.Length > MaxBytes) throw new ProtocolError("RESPONSE_SIZE");
        var header = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await stream.WriteAsync(header, ct);
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
    }

    public static Request Parse(byte[] bytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 6)
                throw new ProtocolError("BAD_ENVELOPE");
            var names = new HashSet<string>(StringComparer.Ordinal) {
                "version", "requestId", "nonce", "issuedAtUtc", "operation", "args"
            };
            foreach (var field in root.EnumerateObject())
                if (!names.Remove(field.Name)) throw new ProtocolError("BAD_ENVELOPE");
            if (names.Count > 0) throw new ProtocolError("BAD_ENVELOPE");
            var req = new Request(
                root.GetProperty("version").GetInt32(),
                root.GetProperty("requestId").GetString() ?? "",
                root.GetProperty("nonce").GetString() ?? "",
                root.GetProperty("issuedAtUtc").GetDateTimeOffset(),
                root.GetProperty("operation").GetString() ?? "",
                root.GetProperty("args").Clone());
            if (req.Args.ValueKind != JsonValueKind.Object || req.Args.EnumerateObject().Any())
                throw new ProtocolError("BAD_ARGUMENTS");
            if (!new[] { "p0.status", "p0.dependency_check", "p0.checkpoint_verify", "p0.scm_attest" }
                .Contains(req.Operation, StringComparer.Ordinal))
                throw new ProtocolError("OPERATION_NOT_ALLOWED");
            return req;
        }
        catch (ProtocolError) { throw; }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException or OverflowException)
        { throw new ProtocolError("INVALID_JSON"); }
    }
}

internal static class AuditLog
{
    public static void Record(string file, string requestId, string operation, string outcome)
    {
        // No request bodies, bearer strings or credentials; only fixed metadata.
        var entry = JsonSerializer.Serialize(new {
            utc = DateTimeOffset.UtcNow, requestId, operation, outcome
        }) + "\n";
        using var writer = new FileStream(file, FileMode.Append, FileAccess.Write,
            FileShare.Read, 4096, FileOptions.WriteThrough);
        var bytes = System.Text.Encoding.UTF8.GetBytes(entry);
        writer.Write(bytes);
        writer.Flush(flushToDisk: true);
    }
}

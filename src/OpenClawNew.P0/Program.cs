using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;

namespace OpenClawNew.P0;

internal static class Program
{
    internal const string PipeName = "OpenClawNew.P0.v1";

    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 20;
        if (args.Length == 1 && args[0] == "--selftest") return SelfTest.Run();
        if (args.Length == 2 && args[0] == "--client")
            return await RunClientAsync(args[1]);
        if (args.Length == 2 && args[0] == "--probe")
            return await ProbeAsync(args[1]);
        if (args.Length == 1 && args[0] == "--service")
        {
            if (!IsSystem()) return 21;
            ServiceBase.Run(new AuthorityService());
            return 0;
        }
        Console.Error.WriteLine("Usage: --service | --client p0.status | --selftest");
        return 2;
    }

    private static bool IsSystem() =>
        WindowsIdentity.GetCurrent().User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;

    private static async Task<int> RunClientAsync(string operation)
    {
        if (!new[] { "p0.status", "p0.dependency_check", "p0.checkpoint_verify", "p0.scm_attest" }
            .Contains(operation, StringComparer.Ordinal))
            return 2;
        using var token = new CancellationTokenSource(TimeSpan.FromSeconds(7));
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
            await pipe.ConnectAsync(3000, token.Token);
            await Wire.WriteAsync(pipe, new {
                version = 1, requestId = Guid.NewGuid().ToString("D"),
                nonce = Guid.NewGuid().ToString("D"),
                issuedAtUtc = DateTimeOffset.UtcNow, operation,
                args = new { }
            }, token.Token);
            var response = await Wire.ReadAsync(pipe, token.Token);
            Console.WriteLine(Encoding.UTF8.GetString(response));
            using var document = JsonDocument.Parse(response);
            return document.RootElement.GetProperty("Ok").GetBoolean() ? 0 : 3;
        }
        catch (Exception ex) when (ex is IOException or System.TimeoutException or OperationCanceledException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("P0_CONNECTION_UNAVAILABLE");
            return 4;
        }
    }

    // Fixed, read-only native IPC negative probes. Only these cases can be sent;
    // there is no generic privileged command or caller-controlled payload.
    private static async Task<int> ProbeAsync(string scenario)
    {
        if (!new[] { "replay", "expired", "future", "bad-args" }
            .Contains(scenario, StringComparer.Ordinal)) return 2;

        async Task<string> SendAsync(string nonce, DateTimeOffset issued, bool badArgs)
        {
            using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(7));
            using var pipe = new NamedPipeClientStream(".", PipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation);
            await pipe.ConnectAsync(3000, ct.Token);
            var payload = badArgs
                ? JsonSerializer.SerializeToUtf8Bytes(new {
                    version = 1, requestId = Guid.NewGuid().ToString("D"),
                    nonce, issuedAtUtc = issued, operation = "p0.status",
                    args = new { forbidden = "fixed_probe" }
                })
                : JsonSerializer.SerializeToUtf8Bytes(new {
                    version = 1, requestId = Guid.NewGuid().ToString("D"),
                    nonce, issuedAtUtc = issued, operation = "p0.status",
                    args = new { }
                });
            await Wire.WriteAsync(pipe, JsonDocument.Parse(payload).RootElement, ct.Token);
            var reply = await Wire.ReadAsync(pipe, ct.Token);
            using var parsed = JsonDocument.Parse(reply);
            return parsed.RootElement.GetProperty("Code").GetString() ?? "";
        }

        try
        {
            var nonce = Guid.NewGuid().ToString("D");
            var now = DateTimeOffset.UtcNow;
            var observed = new List<string>();
            if (scenario == "replay")
            {
                observed.Add(await SendAsync(nonce, now, false));
                observed.Add(await SendAsync(nonce, now, false));
            }
            else
            {
                var date = scenario switch {
                    "expired" => now.AddMinutes(-10),
                    "future" => now.AddMinutes(10),
                    _ => now
                };
                observed.Add(await SendAsync(nonce, date, scenario == "bad-args"));
            }
            var expected = scenario switch {
                "replay" => new[] { "OK", "REPLAY" },
                "expired" => new[] { "EXPIRED" },
                "future" => new[] { "EXPIRED" },
                _ => new[] { "BAD_ARGUMENTS" }
            };
            bool pass = observed.SequenceEqual(expected, StringComparer.Ordinal);
            Console.WriteLine(JsonSerializer.Serialize(new {
                probe = scenario, status = pass ? "PASS" : "FAIL",
                codes = observed.ToArray()
            }));
            return pass ? 0 : 8;
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException
            or System.TimeoutException or JsonException)
        {
            Console.Error.WriteLine("P0_PROBE_TRANSPORT_FAILED");
            return 9;
        }
    }

    private sealed class AuthorityService : ServiceBase
    {
        private CancellationTokenSource? stopper;
        private Task? worker;

        public AuthorityService()
        {
            ServiceName = InstallationPolicy.Name;
            AutoLog = true;
            CanStop = true;
        }

        protected override void OnStart(string[] args)
        {
            var policy = InstallationPolicy.Load(); // fail start if identity/pin/config wrong
            if (!File.Exists(policy.AuditPath))
                throw new ProtocolError("AUDIT_NOT_PROVISIONED");
            stopper = new CancellationTokenSource();
            worker = Task.Run(() => ServeAsync(policy, stopper.Token));
            worker.ContinueWith(t => Environment.FailFast("P0_PIPE_HOST_FAILURE", t.Exception),
                TaskContinuationOptions.OnlyOnFaulted);
        }

        protected override void OnStop()
        {
            stopper?.Cancel();
            try { worker?.Wait(TimeSpan.FromSeconds(8)); }
            catch (AggregateException) { }
            stopper?.Dispose();
        }
    }

    private static PipeSecurity BuildPipeSecurity(string operatorSid)
    {
        var descriptor = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        descriptor.AddAccessRule(new PipeAccessRule(system,
            PipeAccessRights.FullControl, AccessControlType.Allow));
        descriptor.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(operatorSid),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));
        descriptor.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Deny));
        return descriptor;
    }

    private static async Task ServeAsync(InstallationPolicy policy, CancellationToken stop)
    {
        var replay = new ReplayGuard();
        var descriptor = BuildPipeSecurity(policy.OperatorSid);
        while (!stop.IsCancellationRequested)
        {
            using var pipe = NamedPipeServerStreamAcl.Create(
                PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous, Wire.MaxBytes, Wire.MaxBytes, descriptor);
            await pipe.WaitForConnectionAsync(stop);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
            timeout.CancelAfter(TimeSpan.FromSeconds(7));
            await ServeOneAsync(pipe, policy, replay, timeout.Token);
        }
    }

    private static async Task ServeOneAsync(NamedPipeServerStream pipe,
        InstallationPolicy policy, ReplayGuard replay, CancellationToken ct)
    {
        var id = ""; var operation = "";
        Response response;
        try
        {
            var bytes = await Wire.ReadAsync(pipe, ct);
            // The identity must come from the Windows token of the actual named
            // pipe peer; NEVER trust a SID supplied in the request body.
            SecurityIdentifier? caller = null;
            pipe.RunAsClient(() => caller = WindowsIdentity.GetCurrent().User);
            if (caller?.Value != policy.OperatorSid)
                throw new ProtocolError("CALLER_DENIED");

            var req = Wire.Parse(bytes);
            id = req.RequestId;
            operation = req.Operation;
            replay.Admit(req, DateTimeOffset.UtcNow);
            var result = ProtectedDispatcher.Execute(req, policy);
            AuditLog.Record(policy.AuditPath, SafeId(id), operation, "OK");
            response = new Response(true, id, "OK", result);
        }
        catch (ProtocolError ex)
        {
            if (!TryAudit(policy.AuditPath, SafeId(id), SafeOperation(operation), ex.Code))
                response = new Response(false, SafeId(id), "AUDIT_UNAVAILABLE");
            else
                response = new Response(false, SafeId(id), ex.Code);
        }
        catch (Exception)
        {
            if (!TryAudit(policy.AuditPath, SafeId(id), SafeOperation(operation), "INTERNAL_ERROR"))
                response = new Response(false, SafeId(id), "AUDIT_UNAVAILABLE");
            else
                response = new Response(false, SafeId(id), "INTERNAL_ERROR");
        }
        try { await Wire.WriteAsync(pipe, response, ct); }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException
            or OperationCanceledException)
        {
            // A dropped client must not kill the whole protected service.
            // Authorization and audit have already been finalized.
        }
    }

    private static string SafeId(string value) =>
        Guid.TryParseExact(value, "D", out _) ? value : "";
    private static string SafeOperation(string value) =>
        value.Length is > 0 and <= 40 && value.All(c =>
            (c >= 'a' && c <= 'z') || c == '0' || c == '_' || c == '.')
            ? value : "";

    private static bool TryAudit(string path, string id, string operation, string outcome)
    {
        try { AuditLog.Record(path, id, operation, outcome); return true; }
        catch (Exception) { return false; }
    }
}

internal static class SelfTest
{
    public static int Run()
    {
        var passed = 0;
        void Check(bool condition) {
            if (!condition) throw new Exception("SELFTEST_FAILED_" + passed);
            passed++;
        }
        var now = DateTimeOffset.UtcNow;
        Request Good(string op = "p0.status", string? nonce = null) {
            var data = JsonSerializer.SerializeToUtf8Bytes(new {
                version = 1, requestId = Guid.NewGuid().ToString("D"),
                nonce = nonce ?? Guid.NewGuid().ToString("D"),
                issuedAtUtc = now, operation = op, args = new { }
            });
            return Wire.Parse(data);
        }
        bool Rejected(Action action, string code) {
            try { action(); return false; }
            catch (ProtocolError ex) { return ex.Code == code; }
        }
        var guard = new ReplayGuard();
        var valid = Good();
        guard.Admit(valid, now);
        Check(valid.Operation == "p0.status");
        Check(Rejected(() => guard.Admit(valid, now), "REPLAY"));
        Check(Rejected(() => guard.Admit(valid with { Version = 2, Nonce = Guid.NewGuid().ToString("D") }, now), "VERSION_UNSUPPORTED"));
        Check(Rejected(() => guard.Admit(valid with { IssuedAtUtc = now.AddMinutes(-10), Nonce = Guid.NewGuid().ToString("D") }, now), "EXPIRED"));
        Check(Rejected(() => Good("p0.release_apply"), "OPERATION_NOT_ALLOWED"));
        var badArguments = JsonSerializer.SerializeToUtf8Bytes(new {
            version = 1, requestId = Guid.NewGuid().ToString("D"),
            nonce = Guid.NewGuid().ToString("D"), issuedAtUtc = now,
            operation = "p0.status", args = new { command = "whoami" }
        });
        Check(Rejected(() => Wire.Parse(badArguments), "BAD_ARGUMENTS"));
        var unknown = JsonSerializer.SerializeToUtf8Bytes(new {
            version = 1, requestId = Guid.NewGuid().ToString("D"),
            nonce = Guid.NewGuid().ToString("D"), issuedAtUtc = now,
            operation = "p0.status", args = new { }, path = "C:\\"
        });
        Check(Rejected(() => Wire.Parse(unknown), "BAD_ENVELOPE"));
        Check(Good("p0.scm_attest").Operation == "p0.scm_attest");
        Check(Good("p0.dependency_check").Operation == "p0.dependency_check");
        Check(Good("p0.checkpoint_verify").Operation == "p0.checkpoint_verify");
        Check(Rejected(() => Wire.Parse(Encoding.UTF8.GetBytes("{invalid-json")), "INVALID_JSON"));
        Check(Rejected(() => guard.Admit(valid with {
            RequestId = "invalid", Nonce = Guid.NewGuid().ToString("D")
        }, now), "INVALID_ID"));
        Check(Rejected(() => guard.Admit(valid with {
            Nonce = Guid.NewGuid().ToString("D"), IssuedAtUtc = now.AddMinutes(10)
        }, now), "EXPIRED"));
        var wrongArgs = JsonSerializer.SerializeToUtf8Bytes(new {
            version = 1, requestId = Guid.NewGuid().ToString("D"),
            nonce = Guid.NewGuid().ToString("D"), issuedAtUtc = now,
            operation = "p0.status", args = "not-an-object"
        });
        Check(Rejected(() => Wire.Parse(wrongArgs), "BAD_ARGUMENTS"));
        var lengthHeader = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(
            lengthHeader, Wire.MaxBytes + 1);
        Check(Rejected(() => Wire.ReadAsync(new MemoryStream(lengthHeader),
            CancellationToken.None).GetAwaiter().GetResult(), "FRAME_SIZE"));
        Console.WriteLine(JsonSerializer.Serialize(new { tests = passed, failed = 0, type = "PURE_CONTRACT_ONLY_NOT_SCM_E2E" }));
        return 0;
    }
}

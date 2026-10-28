using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace OpenClawNew.P0;

internal sealed record InstallationPolicy(
    int Schema, string ServiceName, string OperatorSid, string InstallRoot, string ServiceExeSha256)
{
    public const string Name = "OpenClawNewP0";

    public static InstallationPolicy Load()
    {
        var binary = Environment.ProcessPath ?? throw new ProtocolError("BINARY_UNKNOWN");
        var root = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(binary)!, ".."));
        var path = Path.Combine(root, "config", "p0-policy.json");
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new ProtocolError("POLICY_UNAVAILABLE");
        var policy = JsonSerializer.Deserialize<InstallationPolicy>(
            File.ReadAllText(path), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new ProtocolError("POLICY_INVALID");
        if (policy.Schema != 1 || policy.ServiceName != Name ||
            !string.Equals(Path.GetFullPath(policy.InstallRoot).TrimEnd(Path.DirectorySeparatorChar),
                root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) ||
            !IsValidOperatorSid(policy.OperatorSid) ||
            policy.ServiceExeSha256.Length != 64 ||
            !policy.ServiceExeSha256.All(Uri.IsHexDigit))
            throw new ProtocolError("POLICY_INVALID");
        if (!policy.AttestedBinary())
            throw new ProtocolError("BINARY_PIN_MISMATCH");
        return policy;
    }

    private static bool IsValidOperatorSid(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try
        {
            var sid = new SecurityIdentifier(value);
            return sid.IsAccountSid() && !sid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }
        catch (ArgumentException) { return false; }
    }

    public string AuditPath => Path.Combine(InstallRoot, "data", "audit.jsonl");

    public bool AttestedBinary()
    {
        var binary = Environment.ProcessPath;
        if (binary is null || !File.Exists(binary) ||
            (File.GetAttributes(binary) & FileAttributes.ReparsePoint) != 0)
            return false;
        using var file = File.Open(binary, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var digest = SHA256.HashData(file);
        return CryptographicOperations.FixedTimeEquals(digest,
            Convert.FromHexString(ServiceExeSha256));
    }
}

internal static class ProtectedDispatcher
{
    public static object Execute(Request req, InstallationPolicy policy)
    {
        // Only exact, zero-parameter operations are currently admitted. No shell,
        // arbitrary service name, filesystem path, or release can be selected.
        return req.Operation switch
        {
            "p0.status" => new {
                service = InstallationPolicy.Name,
                phase = "E1_NATIVE_CANDIDATE",
                authority = "WINDOWS_SCM_PROCESS",
                ready = true,
                operations = new[] {
                    "p0.status", "p0.dependency_check", "p0.checkpoint_verify", "p0.scm_attest"
                }
            },
            "p0.dependency_check" => new {
                operatingSystem = "Windows",
                runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                process64Bit = Environment.Is64BitProcess,
                binaryPinMatches = policy.AttestedBinary()
            },
            "p0.checkpoint_verify" => new {
                item = "P0_INSTALLED_BINARY",
                pinMatches = policy.AttestedBinary(),
                // No arbitrary checkpoint paths; further pinned profiles belong to E2.
                otherCheckpoints = "NOT_IMPLEMENTED"
            },
            "p0.scm_attest" => NativeScmAttestation.CheckOwnService(policy),
            _ => throw new ProtocolError("OPERATION_NOT_ALLOWED")
        };
    }
}

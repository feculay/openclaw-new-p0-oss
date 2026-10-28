using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using System.Security.Principal;
using System.ServiceProcess;

namespace OpenClawNew.P0;

/// <summary>
/// Checks the real Windows SCM database for this product's own P0 service.
/// This is not a complete service-security-descriptor attestation; that
/// additional invariant remains required before production certification.
/// </summary>
internal static class NativeScmAttestation
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ReadControl = 0x00020000;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int ErrorInsufficientBuffer = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigNative
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(
        string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(
        IntPtr scmHandle, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(
        IntPtr serviceHandle, IntPtr buffer, uint bufferSize, out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceObjectSecurity(
        IntPtr serviceHandle, uint securityInformation, byte[]? descriptor,
        uint size, out uint required);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);

    public static object CheckOwnService(InstallationPolicy policy)
    {
        if (!OperatingSystem.IsWindows()) throw new ProtocolError("WINDOWS_REQUIRED");
        var binary = Environment.ProcessPath ?? throw new ProtocolError("BINARY_UNKNOWN");
        var expected = "\"" + Path.GetFullPath(binary) + "\" --service";

        using var stateProbe = new ServiceController(InstallationPolicy.Name);
        ServiceControllerStatus state;
        try { state = stateProbe.Status; }
        catch (InvalidOperationException) { throw new ProtocolError("SCM_SERVICE_MISSING"); }

        var (imagePath, account) = ReadServiceConfig(InstallationPolicy.Name);
        // Never return imagePath, account, machine name or other sensitive
        // SCM metadata to an AI or plugin client. Compare on the authority.
        var imagePinned = string.Equals(imagePath.Trim(), expected,
            StringComparison.OrdinalIgnoreCase);
        var scmAccountMatches = string.Equals(account, "LocalSystem",
            StringComparison.OrdinalIgnoreCase) ||
            string.Equals(account, "NT AUTHORITY\\SYSTEM",
                StringComparison.OrdinalIgnoreCase);
        var actualSystem = WindowsIdentity.GetCurrent().User?
            .IsWellKnown(WellKnownSidType.LocalSystemSid) == true;
        var binaryPinned = policy.AttestedBinary();
        var identityPinned = scmAccountMatches && actualSystem;
        var (daclPinned, broadWriteDenied) = ReadPinnedDacl(policy);
        var configPinned = imagePinned && identityPinned && binaryPinned && daclPinned && broadWriteDenied;
        return new {
            service = InstallationPolicy.Name,
            state = state.ToString().ToUpperInvariant(),
            imagePinned,
            identityPinned,
            binaryShaPinned = binaryPinned,
            configurationPinned = configPinned,
            securityDescriptorPinned = daclPinned,
            broadPrincipalAdministrativeRightsDenied = broadWriteDenied,
            attested = configPinned,
            certification = configPinned ? "SCM_IMAGE_IDENTITY_DACL_PINNED_LAB" : "SCM_ATTESTATION_FAILED"
        };
    }


    private static (bool Pinned, bool BroadRightsDenied) ReadPinnedDacl(InstallationPolicy policy)
    {
        var pinPath = Path.Combine(policy.InstallRoot, "config", "scm-pin.json");
        if (!File.Exists(pinPath) || (File.GetAttributes(pinPath) & FileAttributes.ReparsePoint) != 0)
            throw new ProtocolError("SCM_PIN_MISSING");
        JsonElement pin;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(pinPath));
            pin = doc.RootElement.Clone();
        }
        catch (JsonException) { throw new ProtocolError("SCM_PIN_INVALID"); }
        if (!pin.TryGetProperty("schema", out var schema) ||
            schema.GetString() != "openclawnew.scm-dacl-pin.v1" ||
            !pin.TryGetProperty("service", out var serviceName) ||
            serviceName.GetString() != InstallationPolicy.Name ||
            !pin.TryGetProperty("daclSha256", out var hash))
            throw new ProtocolError("SCM_PIN_INVALID");
        var expected = hash.GetString() ?? "";
        if (expected.Length != 64 || !expected.All(Uri.IsHexDigit))
            throw new ProtocolError("SCM_PIN_INVALID");

        var scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) throw new ProtocolError("SCM_UNAVAILABLE");
        try
        {
            var service = OpenService(scm, InstallationPolicy.Name, ReadControl);
            if (service == IntPtr.Zero) throw new ProtocolError("SCM_DACL_UNAVAILABLE");
            try
            {
                _ = QueryServiceObjectSecurity(service, DaclSecurityInformation, null, 0,
                    out var needed);
                if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer ||
                    needed < 20 || needed > 65536)
                    throw new ProtocolError("SCM_DACL_SIZE_INVALID");
                var bytes = new byte[needed];
                if (!QueryServiceObjectSecurity(service, DaclSecurityInformation,
                    bytes, needed, out _))
                    throw new ProtocolError("SCM_DACL_READ_FAILED");
                var descriptor = new RawSecurityDescriptor(bytes, 0);
                var acl = descriptor.DiscretionaryAcl ??
                    throw new ProtocolError("SCM_NULL_DACL_DENIED");
                var dacl = new byte[acl.BinaryLength];
                acl.GetBinaryForm(dacl, 0);
                var actual = SHA256.HashData(dacl);
                var pinMatched = CryptographicOperations.FixedTimeEquals(
                    actual, Convert.FromHexString(expected));

                var broadSids = new HashSet<string>(StringComparer.Ordinal) {
                    "S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545", "S-1-5-2", "S-1-5-4"
                };
                const int sensitive = 0x00000002 | 0x00000010 | 0x00000020 |
                    0x00000080 | 0x00000100 | 0x00010000 | 0x00040000 |
                    0x00080000 | 0x10000000 | 0x20000000 | 0x40000000;
                bool allowed = true;
                foreach (GenericAce ace in acl)
                {
                    if (ace is not QualifiedAce ca || ca.AceQualifier != AceQualifier.AccessAllowed)
                        continue;
                    if (ca.SecurityIdentifier is null ||
                        !broadSids.Contains(ca.SecurityIdentifier.Value))
                        continue;
                    if ((ca.AccessMask & sensitive) != 0) allowed = false;
                }
                return (pinMatched, allowed);
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }

    private static (string ImagePath, string Account) ReadServiceConfig(string name)
    {
        var scm = OpenSCManager(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero)
            throw new ProtocolError("SCM_UNAVAILABLE");
        try
        {
            var service = OpenService(scm, name, ServiceQueryConfig);
            if (service == IntPtr.Zero)
                throw new ProtocolError("SCM_SERVICE_UNAVAILABLE");
            try
            {
                _ = QueryServiceConfig(service, IntPtr.Zero, 0, out var bytesNeeded);
                if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer ||
                    bytesNeeded < Marshal.SizeOf<QueryServiceConfigNative>() ||
                    bytesNeeded > 65536)
                    throw new ProtocolError("SCM_CONFIG_SIZE_INVALID");
                var buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
                try
                {
                    if (!QueryServiceConfig(service, buffer, bytesNeeded, out _))
                        throw new ProtocolError("SCM_CONFIG_READ_FAILED");
                    var config = Marshal.PtrToStructure<QueryServiceConfigNative>(buffer);
                    return (
                        Marshal.PtrToStringUni(config.BinaryPathName) ?? "",
                        Marshal.PtrToStringUni(config.ServiceStartName) ?? ""
                    );
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
